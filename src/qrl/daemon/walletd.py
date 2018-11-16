# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from concurrent.futures import ThreadPoolExecutor

import os
import logging
import grpc
from time import sleep
from daemonize import Daemonize

from pyqrllib.pyqrllib import hstr2bin, mnemonic2bin, bin2hstr, QRLHelper

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.daemon.helper import logger
from qrl.daemon.helper.DaemonHelper import WalletDecryptionError, Wallet, UNRESERVED_OTS_INDEX_START
from qrl.services.WalletAPIService import WalletAPIService
from qrl.generated import qrl_pb2, qrl_pb2_grpc, qrlwallet_pb2
from qrl.generated.qrlwallet_pb2_grpc import add_WalletAPIServicer_to_server
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.crypto.xmss import XMSS

CONNECTION_TIMEOUT = 30
config.create_path(config.user.wallet_dir)
pid = os.path.join(config.user.wallet_dir, 'qrl_walletd.pid')


class WalletD:
    def __init__(self):
        self._wallet_path = os.path.join(config.user.wallet_dir, 'walletd.json')
        self._public_stub = qrl_pb2_grpc.PublicAPIStub(grpc.insecure_channel(config.user.public_api_server))
        self._wallet = None
        self._passphrase = None
        self.load_wallet()

    def to_plain_blocks(self, block):
        pheader = qrlwallet_pb2.PlainBlockHeader()
        pheader.hash_header = bin2hstr(block.header.hash_header)
        pheader.block_number = block.header.block_number
        pheader.timestamp_seconds = block.header.timestamp_seconds
        pheader.hash_header_prev = bin2hstr(block.header.hash_header_prev)
        pheader.reward_block = block.header.reward_block
        pheader.reward_fee = block.header.reward_fee
        pheader.merkle_root = bin2hstr(block.header.merkle_root)

        pheader.mining_nonce = block.header.mining_nonce
        pheader.extra_nonce = block.header.extra_nonce

        pblock = qrlwallet_pb2.PlainBlock()
        pblock.header.MergeFrom(pheader)

        for tx in block.transactions:
            pblock.transactions.extend([self.to_plain_transaction(tx)])

        for genesis_balance in block.genesis_balance:
            pgb = qrlwallet_pb2.PlainGenesisBalance()
            pgb.address = self.address_to_qaddress(genesis_balance.address)
            pgb.balance = genesis_balance.balance
            pblock.genesis_balance.extend([pgb])

        return pblock

    @staticmethod
    def to_plain_address_amount(address_amount):
        am = qrlwallet_pb2.PlainAddressAmount()
        am.address = bin2hstr(address_amount.address)
        am.amount = address_amount.amount
        return am

    def to_plain_transaction(self, tx):
        ptx = qrlwallet_pb2.PlainTransaction()
        if not tx.WhichOneof('transactionType'):
            return ptx
        if tx.master_addr:
            ptx.master_addr = self.address_to_qaddress(tx.master_addr)
        ptx.fee = tx.fee
        ptx.public_key = bin2hstr(tx.public_key)
        ptx.signature = bin2hstr(tx.signature)
        ptx.nonce = tx.nonce
        ptx.transaction_hash = bin2hstr(tx.transaction_hash)
        if tx.WhichOneof('transactionType') != 'coinbase':
            ptx.signer_addr = self.get_address_from_pk(ptx.public_key)

        if tx.WhichOneof('transactionType') == "transfer":
            ptx.transfer.amounts.extend(tx.transfer.amounts)
            for addr in tx.transfer.addrs_to:
                ptx.transfer.addrs_to.extend([self.address_to_qaddress(addr)])

        elif tx.WhichOneof('transactionType') == 'coinbase':
            ptx.coinbase.addr_to = self.address_to_qaddress(tx.coinbase.addr_to)
            ptx.coinbase.amount = tx.coinbase.amount

        elif tx.WhichOneof('transactionType') == 'lattice_public_key':
            ptx.lattice_public_key.MergeFrom(ptx.lattice_public_key())
            ptx.lattice_public_key.kyber_pk = bin2hstr(tx.lattice_public_key.kyber_pk)
            ptx.lattice_public_key.dilithium_pk = bin2hstr(tx.lattice_public_key.dilithium_pk)

        elif tx.WhichOneof('transactionType') == 'message':
            ptx.message.message_hash = str(tx.message.message_hash)

        elif tx.WhichOneof('transactionType') == 'token':
            ptx.token.symbol = tx.token.symbol
            ptx.token.name = tx.token.name
            ptx.token.owner = self.address_to_qaddress(tx.token.owner)
            ptx.token.decimals = tx.token.decimals
            for initial_balance in tx.token.initial_balances:
                ptx.token.initial_balances.extend([self.to_plain_address_amount(initial_balance)])

        elif tx.WhichOneof('transactionType') == 'transfer_token':
            ptx.transfer_token.token_txhash = bin2hstr(tx.transfer_token.token_txhash)
            ptx.transfer_token.addrs_to.extend(self.addresses_to_qaddress(tx.transfer_token.addrs_to))
            ptx.transfer_token.amounts.extend(tx.transfer_token.amounts)

        elif tx.WhichOneof('transactionType') == 'slave':
            for slave_pk in tx.slave.slave_pks:
                ptx.slave.slave_pks.extend([bin2hstr(slave_pk)])
            ptx.slave.access_types.extend(tx.slave.access_types)

        return ptx

    def generate_slave_tx(self, signer_pk: bytes, slave_pk_list: list, master_addr=None):
        return SlaveTransaction.create(slave_pks=slave_pk_list,
                                       access_types=[0] * len(slave_pk_list),
                                       fee=0,
                                       xmss_pk=signer_pk,
                                       master_addr=master_addr)

    def load_wallet(self):
        self._wallet = Wallet(self._wallet_path)

    @staticmethod
    def address_to_qaddress(address: bytes):
        return 'Q' + bin2hstr(address)

    @staticmethod
    def addresses_to_qaddress(addresses: list):
        qaddresses = []
        for address in addresses:
            qaddresses.append(WalletD.address_to_qaddress(address))
        return qaddresses

    @staticmethod
    def qaddress_to_address(qaddress: str) -> bytes:
        if not qaddress:
            return qaddress
        return bytes(hstr2bin(qaddress[1:]))

    @staticmethod
    def qaddresses_to_address(qaddresses: list) -> list:
        if not qaddresses:
            return qaddresses
        addresses = []
        for qaddress in qaddresses:
            addresses.append(WalletD.qaddress_to_address(qaddress))
        return addresses

    def authenticate(self):
        if not self._passphrase:
            if self._wallet.is_encrypted():
                raise ValueError('Failed: Passphrase Missing')

    def _encrypt_last_item(self):
        if not self._passphrase:
            return
        self._wallet.encrypt_item(len(self._wallet.address_items) - 1, self._passphrase)

    def _get_wallet_index_xmss(self, signer_address: str, ots_index: int):
        index, _ = self._wallet.get_address_item(signer_address)
        if index is None:
            raise Exception("Signer Address Not Found ", signer_address)
        xmss = self._wallet.get_xmss_by_index(index, self._passphrase)
        if ots_index > 0:
            xmss.set_ots_index(ots_index)
        return index, xmss

    def get_pk_list_from_xmss_list(self, slave_xmss_list):
        return [xmss.pk for xmss in slave_xmss_list]

    def add_new_address(self, height=10, hash_function='shake128') -> str:
        self.authenticate()

        if not hash_function:
            hash_function = 'shake128'

        if not height:
            height = 10

        self._wallet.add_new_address(height, hash_function, True)
        self._encrypt_last_item()
        self._wallet.save()
        logger.info("Added New Address")
        return self._wallet.address_items[-1].qaddress

    def add_new_address_with_slaves(self,
                                    height=10,
                                    number_of_slaves=config.user.number_of_slaves,
                                    hash_function='shake128') -> str:
        self.authenticate()

        if not hash_function:
            hash_function = 'shake128'

        if not height:
            height = 10

        if height < 6:
            raise Exception("Height cannot be less than 6")

        if not number_of_slaves:
            number_of_slaves = config.user.number_of_slaves

        if number_of_slaves > 100:
            raise Exception("Number of slaves cannot be more than 100")

        xmss = self._wallet.add_new_address(height, hash_function, True)
        slave_xmss_list = self._wallet.add_slave(index=-1,
                                                 height=height,
                                                 number_of_slaves=number_of_slaves,
                                                 hash_function=hash_function,
                                                 force=True)
        self._encrypt_last_item()

        slave_pk_list = self.get_pk_list_from_xmss_list(slave_xmss_list)
        slave_tx = self.generate_slave_tx(xmss.pk, slave_pk_list)
        self.sign_and_push_transaction(slave_tx, xmss, -1)

        self._wallet.save()
        logger.info("Added New Address With Slaves")
        return self._wallet.address_items[-1].qaddress

    def add_address_from_seed(self, seed=None) -> str:
        self.authenticate()

        words = seed.split()
        if len(words) == 34:
            bin_seed = mnemonic2bin(seed)
        elif len(seed) == 102:
            bin_seed = hstr2bin(seed)
        else:
            raise ValueError("Invalid Seed")

        address_from_seed = XMSS.from_extended_seed(bin_seed)
        if self._wallet.get_xmss_by_qaddress(address_from_seed.qaddress, self._passphrase):
            raise Exception("Address is already in the wallet")
        self._wallet.append_xmss(address_from_seed)
        self._encrypt_last_item()
        self._wallet.save()

        return address_from_seed.qaddress

    def list_address(self) -> list:
        self.authenticate()

        addresses = []
        for item in self._wallet.address_items:
            addresses.append(item.qaddress)

        return addresses

    def remove_address(self, qaddress: str) -> bool:
        self.authenticate()
        if self._wallet.remove(qaddress):
            logger.info("Removed Address %s", qaddress)
            return True

        return False

    def validate_address(self, qaddress: str) -> bool:
        try:
            return AddressState.address_is_valid(bytes(hstr2bin(qaddress[1:])))
        except Exception:
            return False

    def get_recovery_seeds(self, qaddress: str):
        self.authenticate()

        xmss = self._wallet.get_xmss_by_qaddress(qaddress, self._passphrase)
        if xmss:
            logger.info("Recovery seeds requested for %s", qaddress)
            return xmss.hexseed, xmss.mnemonic

        raise ValueError("No such address found in wallet")

    def get_wallet_info(self):
        self.authenticate()

        return self._wallet.wallet_info()

    def get_address_state(self, qaddress: str) -> AddressState:
        request = qrl_pb2.GetAddressStateReq(address=bytes(hstr2bin(qaddress[1:])))

        resp = self._public_stub.GetAddressState(request=request)
        return AddressState(resp.state)

    def sign_and_push_transaction(self,
                                  tx,
                                  xmss,
                                  index,
                                  group_index=None,
                                  slave_index=None,
                                  enable_save=True):
        logger.info("Signing %s transaction by %s | OTS index %s", tx.type, xmss.qaddress, xmss.ots_index)
        tx.sign(xmss)
        if not tx.validate(True):
            raise Exception("Invalid Transaction")

        if enable_save:
            if slave_index == None:  # noqa
                self._wallet.set_ots_index(index, xmss.ots_index)  # Move to next OTS index before broadcasting txn
            else:
                self._wallet.set_slave_ots_index(index, group_index, slave_index, xmss.ots_index)

        push_transaction_req = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        push_transaction_resp = self._public_stub.PushTransaction(push_transaction_req, timeout=CONNECTION_TIMEOUT)
        if push_transaction_resp.error_code != qrl_pb2.PushTransactionResp.SUBMITTED:
            raise Exception(push_transaction_resp.error_description)

    def try_txn_with_last_slave(self, item, index, group_index, xmss=None):
        slave = item.slaves[group_index][-1]

        # Ignore usage of last 5 ots indexes for the last slave in slave group
        if slave.index >= 2 ** slave.height - 5:
            return None

        slave_index = len(item.slaves[group_index]) - 1
        slave_address_state = self.get_address_state(slave.qaddress)

        ots_index = slave_address_state.get_unused_ots_index(slave.index)

        if ots_index == None:  # noqa
            self._wallet.set_slave_ots_index(index,
                                             group_index,
                                             slave_index,
                                             2 ** slave.height)
            return None
        if not xmss:
            target_address_item = slave
            if self._passphrase:
                target_address_item = self._wallet.decrypt_address_item(slave, self._passphrase)
            xmss = self._wallet.get_xmss_by_item(target_address_item, ots_index)
        else:
            xmss.set_ots_index(ots_index)

        return xmss

    def get_slave(self, master_qaddress):
        index, item = self._wallet.get_address_item(master_qaddress)
        if index is None:
            raise Exception("Signer Address Not Found ", master_qaddress)

        # Should we check available OTS for master
        # Get slave list using address state
        address_state = self.get_address_state(master_qaddress)

        slave = item.slaves[-1][0]
        if not address_state.validate_slave_with_access_type(str(bytes(hstr2bin(slave.pk))), [0]):
            if len(item.slaves) == 1:
                qaddress = item.qaddress
                target_address_item = item
                group_index = None
            else:
                qaddress = item.slaves[-2][-1].qaddress
                target_address_item = item.slaves[-2][-1]
                group_index = -2

            address_state = self.get_address_state(qaddress)
            ots_index = address_state.get_unused_ots_index()

            if ots_index >= UNRESERVED_OTS_INDEX_START:
                raise Exception('Fatal Error!!! No reserved OTS index found')

            if self._passphrase:
                target_address_item = self._wallet.decrypt_address_item(target_address_item, self._passphrase)

            xmss = self._wallet.get_xmss_by_item(target_address_item, ots_index)

            slaves_pk = [bytes(hstr2bin(slave_item.pk)) for slave_item in item.slaves[-1]]
            tx = self.generate_slave_tx(xmss.pk,
                                        slaves_pk,
                                        self.qaddress_to_address(master_qaddress))

            self.sign_and_push_transaction(tx,
                                           xmss,
                                           index,
                                           enable_save=False)

            if len(item.slaves) > 1:
                if self.try_txn_with_last_slave(item, index, group_index, xmss):
                    return index, len(item.slaves) - 2, len(item.slaves[group_index]) - 1, xmss

        else:
            if len(item.slaves) > 1:
                group_index = len(item.slaves) - 2
                xmss = self.try_txn_with_last_slave(item, index, group_index)
                if xmss:
                    return index, group_index, len(item.slaves[group_index]) - 1, xmss
            group_index = len(item.slaves) - 1
            last_slaves = item.slaves[-1]
            for slave_index in range(len(last_slaves)):
                slave = last_slaves[slave_index]

                # Check if all ots index has been marked as used
                if slave.index > 2 ** slave.height - 1:
                    continue

                # Ignore usage of last 5 ots indexes for the last slave in slave group
                if slave_index + 1 == len(last_slaves) and slave.index >= 2 ** slave.height - 5:
                    continue

                if self._passphrase:
                    slave = self._wallet.decrypt_address_item(slave, self._passphrase)

                slave_address_state = self.get_address_state(slave.qaddress)

                if slave_index + 1 == len(last_slaves) and slave.index > 2 ** slave.height - 100:

                    ots_index = slave_address_state.get_unused_ots_index(0)
                    if ots_index >= UNRESERVED_OTS_INDEX_START:
                        raise Exception("Fatal Error, no unused reserved OTS index")

                    curr_slave_xmss = self._wallet.get_xmss_by_item(slave, ots_index)

                    slave_xmss_list = self._wallet.add_slave(index=index,
                                                             height=slave.height,
                                                             number_of_slaves=config.user.number_of_slaves,
                                                             passphrase=self._passphrase,
                                                             force=True)
                    slave_pk_list = self.get_pk_list_from_xmss_list(slave_xmss_list)

                    tx = self.generate_slave_tx(bytes(hstr2bin(slave.pk)),
                                                slave_pk_list,
                                                self.qaddress_to_address(item.qaddress))

                    self.sign_and_push_transaction(tx,
                                                   curr_slave_xmss,
                                                   index,
                                                   enable_save=False)

                ots_index = slave_address_state.get_unused_ots_index(slave.index)

                if ots_index == None:  # noqa
                    self._wallet.set_slave_ots_index(index,
                                                     group_index,
                                                     slave_index,
                                                     2 ** slave.height)
                    continue

                slave_xmss = self._wallet.get_xmss_by_item(slave, ots_index)

                return index, group_index, slave_index, slave_xmss

        return index, -1, -1, None

    def get_slave_xmss(self, master_qaddress):
        index, group_index, slave_index, slave_xmss = self.get_slave(master_qaddress)

        return index, group_index, slave_index, slave_xmss

    def get_slave_list(self, qaddress) -> list:
        self.authenticate()
        _, addr_item = self._wallet.get_address_item(qaddress)
        if addr_item is None:
            raise Exception("Address Not Found ", qaddress)
        return addr_item.slaves

    def verify_ots(self, signer_address, xmss, user_ots_index):
        addr_state = self.get_address_state(signer_address)
        verified_ots_index = addr_state.get_unused_ots_index(xmss.ots_index)

        if verified_ots_index == None:  # noqa
            raise Exception("No Unused OTS key found")

        if user_ots_index > 0:
            if verified_ots_index != xmss.ots_index:
                raise Exception("Used OTS Index %s", user_ots_index)
        else:
            xmss.set_ots_index(verified_ots_index)

    def relay_transfer_txn(self,
                           qaddresses_to: list,
                           amounts: list,
                           fee: int,
                           master_qaddress,
                           signer_address: str,
                           ots_index: int):
        self.authenticate()
        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)
        self.verify_ots(signer_address, xmss, user_ots_index=ots_index)

        tx = TransferTransaction.create(addrs_to=self.qaddresses_to_address(qaddresses_to),
                                        amounts=amounts,
                                        fee=fee,
                                        xmss_pk=xmss.pk,
                                        master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, xmss, index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_transfer_txn_by_slave(self,
                                    qaddresses_to: list,
                                    amounts: list,
                                    fee: int,
                                    master_qaddress):
        self.authenticate()
        index, group_index, slave_index, slave_xmss = self.get_slave_xmss(master_qaddress)
        if slave_index == -1:
            raise Exception("No Slave Found")

        tx = TransferTransaction.create(addrs_to=self.qaddresses_to_address(qaddresses_to),
                                        amounts=amounts,
                                        fee=fee,
                                        xmss_pk=slave_xmss.pk,
                                        master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, slave_xmss, index, group_index, slave_index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_message_txn(self,
                          message: str,
                          fee: int,
                          master_qaddress,
                          signer_address: str,
                          ots_index: int):
        self.authenticate()
        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)
        self.verify_ots(signer_address, xmss, user_ots_index=ots_index)

        tx = MessageTransaction.create(message_hash=message.encode(),
                                       fee=fee,
                                       xmss_pk=xmss.pk,
                                       master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, xmss, index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_message_txn_by_slave(self,
                                   message: str,
                                   fee: int,
                                   master_qaddress):
        self.authenticate()
        index, group_index, slave_index, slave_xmss = self.get_slave_xmss(master_qaddress)
        if slave_index == -1:
            raise Exception("No Slave Found")

        tx = MessageTransaction.create(message_hash=message.encode(),
                                       fee=fee,
                                       xmss_pk=slave_xmss.pk,
                                       master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, slave_xmss, index, group_index, slave_index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_token_txn(self,
                        symbol: str,
                        name: str,
                        owner_qaddress: str,
                        decimals: int,
                        qaddresses: list,
                        amounts: list,
                        fee: int,
                        master_qaddress,
                        signer_address: str,
                        ots_index: int):
        self.authenticate()

        if len(qaddresses) != len(amounts):
            raise Exception("Number of Addresses & Amounts Mismatch")

        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)
        self.verify_ots(signer_address, xmss, user_ots_index=ots_index)

        initial_balances = []
        for idx, qaddress in enumerate(qaddresses):
            initial_balances.append(qrl_pb2.AddressAmount(address=self.qaddress_to_address(qaddress),
                                                          amount=amounts[idx]))
        tx = TokenTransaction.create(symbol=symbol.encode(),
                                     name=name.encode(),
                                     owner=self.qaddress_to_address(owner_qaddress),
                                     decimals=decimals,
                                     initial_balances=initial_balances,
                                     fee=fee,
                                     xmss_pk=xmss.pk,
                                     master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, xmss, index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_token_txn_by_slave(self,
                                 symbol: str,
                                 name: str,
                                 owner_qaddress: str,
                                 decimals: int,
                                 qaddresses: list,
                                 amounts: list,
                                 fee: int,
                                 master_qaddress):
        self.authenticate()

        if len(qaddresses) != len(amounts):
            raise Exception("Number of Addresses & Amounts Mismatch")

        index, group_index, slave_index, slave_xmss = self.get_slave_xmss(master_qaddress)
        if slave_index == -1:
            raise Exception("No Slave Found")

        initial_balances = []
        for idx, qaddress in enumerate(qaddresses):
            initial_balances.append(qrl_pb2.AddressAmount(address=self.qaddress_to_address(qaddress),
                                                          amount=amounts[idx]))
        tx = TokenTransaction.create(symbol=symbol.encode(),
                                     name=name.encode(),
                                     owner=self.qaddress_to_address(owner_qaddress),
                                     decimals=decimals,
                                     initial_balances=initial_balances,
                                     fee=fee,
                                     xmss_pk=slave_xmss.pk,
                                     master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, slave_xmss, index, group_index, slave_index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_transfer_token_txn(self,
                                 qaddresses_to: list,
                                 amounts: list,
                                 token_txhash: str,
                                 fee: int,
                                 master_qaddress,
                                 signer_address: str,
                                 ots_index: int):
        self.authenticate()
        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)
        self.verify_ots(signer_address, xmss, user_ots_index=ots_index)

        tx = TransferTokenTransaction.create(token_txhash=bytes(hstr2bin(token_txhash)),
                                             addrs_to=self.qaddresses_to_address(qaddresses_to),
                                             amounts=amounts,
                                             fee=fee,
                                             xmss_pk=xmss.pk,
                                             master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, xmss, index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_transfer_token_txn_by_slave(self,
                                          qaddresses_to: list,
                                          amounts: list,
                                          token_txhash: str,
                                          fee: int,
                                          master_qaddress):
        self.authenticate()
        index, group_index, slave_index, slave_xmss = self.get_slave_xmss(master_qaddress)
        if slave_index == -1:
            raise Exception("No Slave Found")

        tx = TransferTokenTransaction.create(token_txhash=bytes(hstr2bin(token_txhash)),
                                             addrs_to=self.qaddresses_to_address(qaddresses_to),
                                             amounts=amounts,
                                             fee=fee,
                                             xmss_pk=slave_xmss.pk,
                                             master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, slave_xmss, index, group_index, slave_index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_slave_txn(self,
                        slave_pks: list,
                        access_types: list,
                        fee: int,
                        master_qaddress,
                        signer_address: str,
                        ots_index: int):
        self.authenticate()
        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)
        self.verify_ots(signer_address, xmss, user_ots_index=ots_index)

        tx = SlaveTransaction.create(slave_pks=slave_pks,
                                     access_types=access_types,
                                     fee=fee,
                                     xmss_pk=xmss.pk,
                                     master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, xmss, index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_slave_txn_by_slave(self,
                                 slave_pks: list,
                                 access_types: list,
                                 fee: int,
                                 master_qaddress):
        self.authenticate()
        index, group_index, slave_index, slave_xmss = self.get_slave_xmss(master_qaddress)
        if slave_index == -1:
            raise Exception("No Slave Found")

        tx = SlaveTransaction.create(slave_pks=slave_pks,
                                     access_types=access_types,
                                     fee=fee,
                                     xmss_pk=slave_xmss.pk,
                                     master_addr=self.qaddress_to_address(master_qaddress))

        self.sign_and_push_transaction(tx, slave_xmss, index, group_index, slave_index)

        return self.to_plain_transaction(tx.pbdata)

    def encrypt_wallet(self, passphrase: str):
        if self._wallet.is_encrypted():
            raise Exception('Wallet Already Encrypted')
        if not passphrase:
            raise Exception("Missing Passphrase")
        if len(self._wallet.address_items) == 0:
            raise ValueError('Cannot be encrypted as wallet does not have any address.')
        self._wallet.encrypt(passphrase)
        self._wallet.save()
        logger.info("Wallet Encrypted")

    def lock_wallet(self):
        if not self._wallet.is_encrypted():
            raise Exception('You cannot lock an unencrypted Wallet')

        self._passphrase = None
        logger.info("Wallet Locked")

    def unlock_wallet(self, passphrase: str):
        if not self._wallet.is_encrypted():
            raise Exception('You cannot unlock an unencrypted Wallet')

        self._passphrase = passphrase
        self._wallet.decrypt(passphrase, first_address_only=True)  # Check if Password Correct
        self._wallet.encrypt_item(0, passphrase)  # Re-Encrypt first address item
        logger.info("Wallet Unlocked")

    def change_passphrase(self, old_passphrase: str, new_passphrase: str):
        if len(old_passphrase) == 0:
            raise Exception('Missing Old Passphrase')

        if len(new_passphrase) == 0:
            raise Exception('Missing New Passphrase')

        if old_passphrase == new_passphrase:
            raise Exception('Old Passphrase and New Passphrase cannot be same')

        self._passphrase = old_passphrase

        if not self._wallet:
            self.unlock_wallet(old_passphrase)
        try:
            self._wallet.decrypt(old_passphrase)
        except WalletDecryptionError:
            raise ValueError('Invalid Old Passphrase')

        self._wallet.encrypt(new_passphrase)
        self._wallet.save()
        self.lock_wallet()
        logger.info("Passphrase Changed")

    def get_transactions_by_address(self, qaddress: str) -> tuple:
        address = self.qaddress_to_address(qaddress)
        response = self._public_stub.GetTransactionsByAddress(qrl_pb2.GetTransactionsByAddressReq(address=address))
        return response.mini_transactions, response.balance

    def get_transaction(self, tx_hash: str):
        txhash = bytes(hstr2bin(tx_hash))
        response = self._public_stub.GetTransaction(qrl_pb2.GetTransactionReq(tx_hash=txhash))
        block_header_hash = None
        if response.block_header_hash:
            block_header_hash = bin2hstr(response.block_header_hash)
        return self.to_plain_transaction(response.tx), str(response.confirmations), response.block_number, block_header_hash

    def get_balance(self, qaddress: str) -> int:
        address = self.qaddress_to_address(qaddress)
        response = self._public_stub.GetBalance(qrl_pb2.GetBalanceReq(address=address))
        return response.balance

    def get_ots(self, qaddress: str):
        address = self.qaddress_to_address(qaddress)
        response = self._public_stub.GetOTS(qrl_pb2.GetOTSReq(address=address))
        return response.ots_bitfield, response.next_unused_ots_index

    def get_height(self) -> int:
        response = self._public_stub.GetHeight(qrl_pb2.GetHeightReq())
        return response.height

    def get_block(self, header_hash: str):
        headerhash = bytes(hstr2bin(header_hash))
        response = self._public_stub.GetBlock(qrl_pb2.GetBlockReq(header_hash=headerhash))
        return self.to_plain_blocks(response.block)

    def get_block_by_number(self, block_number: int):
        response = self._public_stub.GetBlockByNumber(qrl_pb2.GetBlockByNumberReq(block_number=block_number))
        return self.to_plain_blocks(response.block)

    def get_address_from_pk(self, pk: str) -> str:
        return self.address_to_qaddress(QRLHelper.getAddress(bytes(hstr2bin(pk))))

    def get_node_info(self):
        return self._public_stub.GetNodeState(qrl_pb2.GetNodeStateReq())


def run():
    logger.initialize_default(force_console_output=True).setLevel(logging.INFO)
    file_handler = logger.log_to_file()
    file_handler.setLevel(logging.INFO)

    LOG_FORMAT_CUSTOM = '%(asctime)s| %(levelname)s : %(message)s'  # noqa

    logger.set_colors(False, LOG_FORMAT_CUSTOM)
    logger.set_unhandled_exception_handler()

    walletd = WalletD()  # noqa
    wallet_server = grpc.server(ThreadPoolExecutor(max_workers=config.user.wallet_api_threads),
                                maximum_concurrent_rpcs=config.user.wallet_api_max_concurrent_rpc)
    add_WalletAPIServicer_to_server(WalletAPIService(walletd), wallet_server)

    wallet_server.add_insecure_port("{0}:{1}".format(config.user.wallet_api_host,
                                                     config.user.wallet_api_port))
    wallet_server.start()

    logger.info("WalletAPIService Started")

    try:
        while True:
            sleep(60)
    except Exception:  # noqa
        wallet_server.stop(0)


def main():
    daemon = Daemonize(app="qrl_walletd", pid=pid, action=run)
    daemon.start()


if __name__ == '__main__':
    main()
