# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from concurrent.futures import ThreadPoolExecutor

import os
import grpc
from time import sleep
from daemonize import Daemonize

from pyqrllib.pyqrllib import hstr2bin, mnemonic2bin, bin2hstr, QRLHelper

from qrl.core import config
from qrl.core.Wallet import WalletDecryptionError
from qrl.services.WalletAPIService import WalletAPIService
from qrl.generated import qrl_pb2, qrl_pb2_grpc, qrlwallet_pb2
from qrl.generated.qrlwallet_pb2_grpc import add_WalletAPIServicer_to_server
from qrl.core.Wallet import Wallet
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.crypto.xmss import XMSS

CONNECTION_TIMEOUT = 15
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
            ptx.message.message_hash = tx.message.message_hash

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
        xmss = self._wallet.get_xmss_by_index(index, self._passphrase)
        if ots_index > 0:
            xmss.set_ots_index(ots_index)
        return index, xmss

    def add_new_address(self, height=10, hash_function='shake128') -> str:
        self.authenticate()

        if not hash_function:
            hash_function = 'shake128'

        if not height:
            height = 10

        self._wallet.add_new_address(height, hash_function, True)
        self._encrypt_last_item()
        self._wallet.save()
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

        return self._wallet.remove(qaddress)

    def get_recovery_seeds(self, qaddress: str):
        self.authenticate()

        xmss = self._wallet.get_xmss_by_qaddress(qaddress, self._passphrase)
        if xmss:
            return xmss.hexseed, xmss.mnemonic

        raise ValueError("No such address found in wallet")

    def get_wallet_info(self):
        self.authenticate()

        return self._wallet.wallet_info()

    def _push_transaction(self, tx, xmss):
        tx.sign(xmss)
        if not tx.validate(True):
            return None

        push_transaction_req = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        push_transaction_resp = self._public_stub.PushTransaction(push_transaction_req, timeout=CONNECTION_TIMEOUT)
        if push_transaction_resp.error_code != qrl_pb2.PushTransactionResp.SUBMITTED:
            raise Exception(push_transaction_resp.error_description)

    def relay_transfer_txn(self,
                           qaddresses_to: list,
                           amounts: list,
                           fee: int,
                           master_qaddress,
                           signer_address: str,
                           ots_index: int):
        self.authenticate()
        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)

        tx = TransferTransaction.create(addrs_to=self.qaddresses_to_address(qaddresses_to),
                                        amounts=amounts,
                                        fee=fee,
                                        xmss_pk=xmss.pk,
                                        master_addr=self.qaddress_to_address(master_qaddress))

        self._push_transaction(tx, xmss)
        self._wallet.set_ots_index(index, xmss.ots_index)

        return self.to_plain_transaction(tx.pbdata)

    def relay_message_txn(self,
                          message: str,
                          fee: int,
                          master_qaddress,
                          signer_address: str,
                          ots_index: int):
        self.authenticate()
        index, xmss = self._get_wallet_index_xmss(signer_address, ots_index)

        tx = MessageTransaction.create(message_hash=message.encode(),
                                       fee=fee,
                                       xmss_pk=xmss.pk,
                                       master_addr=self.qaddress_to_address(master_qaddress))

        self._push_transaction(tx, xmss)
        self._wallet.set_ots_index(index, xmss.ots_index)

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

        self._push_transaction(tx, xmss)
        self._wallet.set_ots_index(index, xmss.ots_index)

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

        tx = TransferTokenTransaction.create(token_txhash=bytes(hstr2bin(token_txhash)),
                                             addrs_to=self.qaddresses_to_address(qaddresses_to),
                                             amounts=amounts,
                                             fee=fee,
                                             xmss_pk=xmss.pk,
                                             master_addr=self.qaddress_to_address(master_qaddress))

        self._push_transaction(tx, xmss)
        self._wallet.set_ots_index(index, xmss.ots_index)

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

        tx = SlaveTransaction.create(slave_pks=slave_pks,
                                     access_types=access_types,
                                     fee=fee,
                                     xmss_pk=xmss.pk,
                                     master_addr=self.qaddress_to_address(master_qaddress))

        self._push_transaction(tx, xmss)
        self._wallet.set_ots_index(index, xmss.ots_index)

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

    def lock_wallet(self):
        self._passphrase = None

    def unlock_wallet(self, passphrase: str):
        self._passphrase = passphrase
        self._wallet.decrypt(passphrase, first_address_only=True)
        self.load_wallet()

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

    def get_transactions_by_address(self, qaddress: str) -> tuple:
        address = self.qaddress_to_address(qaddress)
        response = self._public_stub.GetTransactionsByAddress(qrl_pb2.GetTransactionsByAddressReq(address=address))
        return response.mini_transactions, response.balance

    def get_transaction(self, tx_hash: str):
        txhash = bytes(hstr2bin(tx_hash))
        response = self._public_stub.GetTransaction(qrl_pb2.GetTransactionReq(tx_hash=txhash))
        return self.to_plain_transaction(response.tx), response.confirmations

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


def run():
    walletd = WalletD()
    wallet_server = grpc.server(ThreadPoolExecutor(max_workers=config.user.wallet_api_threads),
                                maximum_concurrent_rpcs=config.user.wallet_api_max_concurrent_rpc)
    add_WalletAPIServicer_to_server(WalletAPIService(walletd), wallet_server)

    wallet_server.add_insecure_port("{0}:{1}".format(config.user.wallet_api_host,
                                                     config.user.wallet_api_port))
    wallet_server.start()

    try:
        while True:
            sleep(60)
    except Exception:
        wallet_server.stop(0)


def main():
    daemon = Daemonize(app="qrl_walletd", pid=pid, action=run)
    daemon.start()


if __name__ == '__main__':
    main()
