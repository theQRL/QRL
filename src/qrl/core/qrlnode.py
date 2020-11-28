# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from decimal import Decimal
from typing import Optional, List, Iterator, Tuple

from pyqrllib.pyqrllib import QRLHelper, bin2hstr
from twisted.internet import reactor

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.ESyncState import ESyncState
from qrl.core.misc import ntp
from qrl.core.misc.logger import logger
from qrl.core.node import POW, SyncState
from qrl.core.p2p.p2pChainManager import P2PChainManager
from qrl.core.p2p.p2pPeerManager import P2PPeerManager
from qrl.core.p2p.p2pTxManagement import P2PTxManagement
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.txs.multisig.MultiSigCreate import MultiSigCreate
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from qrl.core.txs.LatticeTransaction import LatticeTransaction
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.generated import qrl_pb2


class QRLNode:
    def __init__(self, mining_address: bytes):
        self.start_time = ntp.getTime()
        self._sync_state = SyncState()

        self.peer_manager = P2PPeerManager()
        self.peer_manager.load_peer_addresses()

        self.p2pchain_manager = P2PChainManager()

        self.tx_manager = P2PTxManagement()

        self._chain_manager = None  # FIXME: REMOVE. This is temporary
        self._p2pfactory = None  # FIXME: REMOVE. This is temporary

        self._pow = None

        self.mining_address = mining_address

        reactor.callLater(10, self.monitor_chain_state)

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    @property
    def version(self):
        return config.dev.version

    @property
    def sync_state(self) -> SyncState:
        return self._sync_state

    @property
    def state(self):
        if self._p2pfactory is None:
            return ESyncState.unknown.value
        # FIXME
        return self._p2pfactory.sync_state.state.value

    @property
    def num_connections(self):
        if self._p2pfactory is None:
            return 0
        return self._p2pfactory.num_connections

    @property
    def num_known_peers(self):
        return len(self.peer_manager.known_peer_addresses)

    @property
    def uptime(self):
        return ntp.getTime() - self.start_time

    @property
    def block_height(self):
        return self._chain_manager.height

    @property
    def epoch(self):
        if not self._chain_manager.last_block:
            return 0
        return self._chain_manager.last_block.block_number // config.dev.blocks_per_epoch

    @property
    def uptime_network(self):
        block_one = self._chain_manager.get_block_by_number(1)
        network_uptime = 0
        if block_one:
            network_uptime = ntp.getTime() - block_one.timestamp
        return network_uptime

    @property
    def block_last_reward(self):
        if not self._chain_manager.last_block:
            return 0

        return self._chain_manager.last_block.block_reward

    @property
    def block_time_mean(self):
        block = self._chain_manager.last_block

        prev_block_metadata = self._chain_manager.get_block_metadata(block.prev_headerhash)
        if prev_block_metadata is None:
            return config.dev.block_timing_in_seconds

        movavg = self._chain_manager.get_measurement(config.dev,
                                                     block.timestamp,
                                                     block.prev_headerhash,
                                                     prev_block_metadata)
        return movavg

    @property
    def block_time_sd(self):
        # FIXME: Keep a moving var
        return 0

    @property
    def coin_supply(self):
        # FIXME: Keep a moving var
        return self._chain_manager.total_coin_supply

    @property
    def coin_supply_max(self):
        # FIXME: Keep a moving var
        return config.dev.max_coin_supply

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def get_peers_stat(self) -> list:
        return self.peer_manager.get_peers_stat()

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def monitor_chain_state(self):
        self.peer_manager.monitor_chain_state()

        last_block = self._chain_manager.last_block
        block_metadata = self._chain_manager.get_block_metadata(last_block.headerhash)
        node_chain_state = qrl_pb2.NodeChainState(block_number=last_block.block_number,
                                                  header_hash=last_block.headerhash,
                                                  cumulative_difficulty=bytes(block_metadata.cumulative_difficulty),
                                                  version=config.dev.version,
                                                  timestamp=ntp.getTime())

        self.peer_manager.broadcast_chain_state(node_chain_state=node_chain_state)
        channel = self.peer_manager.get_better_difficulty(block_metadata.cumulative_difficulty)
        logger.debug('Got better difficulty %s', channel)
        if channel:
            logger.debug('Connection id >> %s', channel.peer)
            channel.send_get_headerhash_list(self._chain_manager.height)
        reactor.callLater(config.user.chain_state_broadcast_period, self.monitor_chain_state)

    # FIXME: REMOVE. This is temporary
    def set_chain_manager(self, chain_manager: ChainManager):
        self._chain_manager = chain_manager

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def start_pow(self, mining_thread_count):
        self._pow = POW(chain_manager=self._chain_manager,
                        p2p_factory=self._p2pfactory,
                        sync_state=self._sync_state,
                        time_provider=ntp,
                        mining_address=self.mining_address,
                        mining_thread_count=mining_thread_count)

        self._pow.start()

    def start_listening(self):
        self._p2pfactory = P2PFactory(chain_manager=self._chain_manager,
                                      sync_state=self.sync_state,
                                      qrl_node=self)  # FIXME: Try to avoid cyclic references

        self.peer_manager.set_p2p_factory(self._p2pfactory)
        self._p2pfactory.start_listening()

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    @staticmethod
    def validate_amount(amount_str: str) -> bool:
        # FIXME: Refactored code. Review Decimal usage all over the code
        Decimal(amount_str)
        return True

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    @staticmethod
    def create_multi_sig_txn(signatories: list,
                             weights: list,
                             threshold: int,
                             fee: int,
                             xmss_pk: bytes,
                             master_addr: bytes):
        return MultiSigCreate.create(signatories=signatories,
                                     weights=weights,
                                     threshold=threshold,
                                     fee=fee,
                                     xmss_pk=xmss_pk,
                                     master_addr=master_addr)

    @staticmethod
    def create_multi_sig_spend_txn(multi_sig_address: bytes,
                                   addrs_to: list,
                                   amounts: list,
                                   expiry_block_number: int,
                                   fee: int,
                                   xmss_pk: bytes,
                                   master_addr: bytes):
        return MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                    addrs_to=addrs_to,
                                    amounts=amounts,
                                    expiry_block_number=expiry_block_number,
                                    fee=fee,
                                    xmss_pk=xmss_pk,
                                    master_addr=master_addr)

    @staticmethod
    def create_multi_sig_vote_txn(shared_key: bytes,
                                  unvote: bool,
                                  fee: int,
                                  xmss_pk: bytes,
                                  master_addr: bytes):
        return MultiSigVote.create(shared_key=shared_key,
                                   unvote=unvote,
                                   fee=fee,
                                   xmss_pk=xmss_pk,
                                   master_addr=master_addr)

    @staticmethod
    def create_message_txn(message_hash: bytes,
                           addr_to: bytes,
                           fee: int,
                           xmss_pk: bytes,
                           master_addr: bytes):
        return MessageTransaction.create(message_hash=message_hash,
                                         addr_to=addr_to,
                                         fee=fee,
                                         xmss_pk=xmss_pk,
                                         master_addr=master_addr)

    @staticmethod
    def create_token_txn(symbol: bytes,
                         name: bytes,
                         owner: bytes,
                         decimals: int,
                         initial_balances,
                         fee: int,
                         xmss_pk: bytes,
                         master_addr: bytes):
        return TokenTransaction.create(symbol,
                                       name,
                                       owner,
                                       decimals,
                                       initial_balances,
                                       fee,
                                       xmss_pk,
                                       master_addr)

    @staticmethod
    def create_transfer_token_txn(addrs_to: list,
                                  token_txhash: bytes,
                                  amounts: list,
                                  fee: int,
                                  xmss_pk: bytes,
                                  master_addr: bytes):
        return TransferTokenTransaction.create(token_txhash,
                                               addrs_to,
                                               amounts,
                                               fee,
                                               xmss_pk,
                                               master_addr)

    def create_send_tx(self,
                       addrs_to: list,
                       amounts: list,
                       message_data: bytes,
                       fee: int,
                       xmss_pk: bytes,
                       master_addr: bytes) -> TransferTransaction:
        addr_from = self.get_addr_from(xmss_pk, master_addr)
        balance = self._chain_manager.get_address_balance(addr_from)
        if sum(amounts) + fee > balance:
            raise ValueError("Not enough funds in the source address")

        return TransferTransaction.create(addrs_to=addrs_to,
                                          amounts=amounts,
                                          message_data=message_data,
                                          fee=fee,
                                          xmss_pk=xmss_pk,
                                          master_addr=master_addr)

    @staticmethod
    def create_slave_tx(slave_pks: list,
                        access_types: list,
                        fee: int,
                        xmss_pk: bytes,
                        master_addr: bytes) -> SlaveTransaction:
        return SlaveTransaction.create(slave_pks=slave_pks,
                                       access_types=access_types,
                                       fee=fee,
                                       xmss_pk=xmss_pk,
                                       master_addr=master_addr)

    @staticmethod
    def create_lattice_tx(pk1: bytes,
                          pk2: bytes,
                          pk3: bytes,
                          fee: int,
                          xmss_pk: bytes,
                          master_addr: bytes) -> LatticeTransaction:
        return LatticeTransaction.create(pk1=pk1,
                                         pk2=pk2,
                                         pk3=pk3,
                                         fee=fee,
                                         xmss_pk=xmss_pk,
                                         master_addr=master_addr)

    # FIXME: Rename this appropriately
    def submit_send_tx(self, tx) -> bool:
        if tx is None:
            raise ValueError("The transaction was empty")

        if self._chain_manager.tx_pool.is_full_pending_transaction_pool():
            raise ValueError("Pending Transaction Pool is full")

        return self._p2pfactory.add_unprocessed_txn(tx, ip=None)  # TODO (cyyber): Replace None with IP made API request

    @staticmethod
    def get_addr_from(xmss_pk, master_addr):
        if master_addr:
            return master_addr

        return bytes(QRLHelper.getAddress(xmss_pk))

    def get_address_is_used(self, address: bytes) -> bool:
        if not OptimizedAddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        return self._chain_manager.get_address_is_used(address)

    def get_address_state(self,
                          address: bytes,
                          exclude_ots_bitfield: bool = False,
                          exclude_transaction_hashes: bool = False) -> AddressState:
        if address != config.dev.coinbase_address and not AddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        address_state = self._chain_manager.get_address_state(address,
                                                              exclude_ots_bitfield,
                                                              exclude_transaction_hashes)

        return address_state

    def get_optimized_address_state(self, address: bytes) -> OptimizedAddressState:
        if address != config.dev.coinbase_address and not OptimizedAddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        address_state = self._chain_manager.get_optimized_address_state(address)

        return address_state

    def get_multi_sig_address_state(self, address: bytes) -> MultiSigAddressState:
        if not MultiSigAddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        multi_sig_address_state = self._chain_manager.get_multi_sig_address_state(address)

        return multi_sig_address_state

    def get_ots(self,
                address: bytes,
                page_from: int,
                page_count: int,
                unused_ots_index_from: int) -> (list, Optional[int], bool):
        if not OptimizedAddressState.address_is_valid(address):
            return None, None, None

        max_bitfield = 2 ** OptimizedAddressState.get_height_from_address(address)
        max_pages = (max_bitfield // config.dev.ots_tracking_per_page) + 1
        page_from = min(page_from, max_pages)
        max_pages = min(page_from + page_count - 1, max_pages)

        bitfields = list()
        for page in range(page_from, max_pages + 1):
            bitfield = self._chain_manager.get_bitfield(address, page)
            bitfields.append(qrl_pb2.OTSBitfieldByPage(ots_bitfield=bitfield, page_number=page))

        unused_ots_index = self._chain_manager.get_unused_ots_index2(address, unused_ots_index_from)
        unused_ots_index_found = unused_ots_index is not None

        return bitfields, unused_ots_index, unused_ots_index_found

    def is_slave(self, master_address: bytes, slave_pk: bytes):
        return self._chain_manager.is_slave(master_address, slave_pk)

    def get_all_address_state(self) -> list:
        return self._chain_manager.get_all_address_state()

    def _load_transaction_hashes(self, address: bytes, item_per_page: int, page_number: int) -> list:
        address_state = self._chain_manager.get_optimized_address_state(address)
        start_item_index = max(0, address_state.transaction_hash_count() - item_per_page * page_number)
        end_item_index = min(address_state.transaction_hash_count(), start_item_index + item_per_page)

        transaction_hashes = self._chain_manager.get_transaction_hashes(address,
                                                                        start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        transaction_hashes = transaction_hashes[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index:
            actual_start_item_index += config.dev.data_per_page
            transaction_hashes.extend(self._chain_manager.get_transaction_hashes(address,
                                                                                 actual_start_item_index))
        return transaction_hashes[:item_per_page][-1::-1]

    def _load_multi_sig_spend_txn_hashes(self,
                                         address: bytes,
                                         item_per_page: int,
                                         page_number: int,
                                         mode: int) -> list:
        if OptimizedAddressState.address_is_valid(address):
            address_state = self._chain_manager.get_optimized_address_state(address)
        elif MultiSigAddressState.address_is_valid(address):
            address_state = self._chain_manager.get_multi_sig_address_state(address)
        else:
            return []

        start_item_index = max(0, address_state.multi_sig_spend_count() - item_per_page * page_number)
        end_item_index = min(address_state.multi_sig_spend_count(), start_item_index + item_per_page)

        if mode > 0:
            start_item_index = 0
            end_item_index = address_state.multi_sig_spend_count()

        transaction_hashes = self._chain_manager.get_multi_sig_spend_txn_hashes(address,
                                                                                start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        multi_sig_spend_txn_hashes = transaction_hashes[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index and len(multi_sig_spend_txn_hashes) < item_per_page:
            actual_start_item_index += config.dev.data_per_page
            multi_sig_spend_txn_hashes.extend(self._chain_manager.get_multi_sig_spend_txn_hashes(address,
                                                                                                 actual_start_item_index))
        return multi_sig_spend_txn_hashes[:item_per_page][-1::-1]

    def _load_token_transaction_hashes(self, address: bytes, item_per_page: int, page_number: int) -> list:
        address_state = self._chain_manager.get_optimized_address_state(address)
        start_item_index = max(0, address_state.tokens_count() - item_per_page * page_number)
        end_item_index = min(address_state.tokens_count(), start_item_index + item_per_page)

        transaction_hashes = self._chain_manager.get_token_transaction_hashes(address,
                                                                              start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        token_transaction_hashes = transaction_hashes[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index:
            actual_start_item_index += config.dev.data_per_page
            token_transaction_hashes.extend(self._chain_manager.get_token_transaction_hashes(address,
                                                                                             actual_start_item_index))
        return token_transaction_hashes[:item_per_page][-1::-1]

    def _load_slave_transaction_hashes(self, address: bytes, item_per_page: int, page_number: int) -> list:
        address_state = self._chain_manager.get_optimized_address_state(address)
        start_item_index = max(0, address_state.slaves_count() - item_per_page * page_number)
        end_item_index = min(address_state.slaves_count(), start_item_index + item_per_page)

        if start_item_index < 0:
            return []

        transaction_hashes = self._chain_manager.get_slave_transaction_hashes(address,
                                                                              start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        token_transaction_hashes = transaction_hashes[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index:
            actual_start_item_index += config.dev.data_per_page
            token_transaction_hashes.extend(self._chain_manager.get_slave_transaction_hashes(address,
                                                                                             actual_start_item_index))
        return token_transaction_hashes[:item_per_page][-1::-1]

    def _load_lattice_pks_transaction_hashes(self, address: bytes, item_per_page: int, page_number: int) -> list:
        address_state = self._chain_manager.get_optimized_address_state(address)
        start_item_index = max(0, address_state.lattice_pk_count() - item_per_page * page_number)
        end_item_index = min(address_state.lattice_pk_count(), start_item_index + item_per_page)

        transaction_hashes = self._chain_manager.get_lattice_pks_transaction_hashes(address,
                                                                                    start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        lattice_pks_transaction_hashes = transaction_hashes[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index:
            actual_start_item_index += config.dev.data_per_page
            lattice_pks_transaction_hashes.extend(self._chain_manager.get_lattice_pks_transaction_hashes(address,
                                                                                                         actual_start_item_index))
        return lattice_pks_transaction_hashes[:item_per_page][-1::-1]

    def _load_multi_sig_addresses(self, address: bytes, item_per_page: int, page_number: int) -> list:
        address_state = self._chain_manager.get_optimized_address_state(address)
        start_item_index = max(0, address_state.multi_sig_address_count() - item_per_page * page_number)
        end_item_index = min(address_state.multi_sig_address_count(), start_item_index + item_per_page)

        multi_sig_addresses = self._chain_manager.get_multi_sig_addresses(address,
                                                                          start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        multi_sig_addresses = multi_sig_addresses[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index:
            actual_start_item_index += config.dev.data_per_page
            multi_sig_addresses.extend(self._chain_manager.get_multi_sig_addresses(address,
                                                                                   actual_start_item_index))
        return multi_sig_addresses[:item_per_page][-1::-1]

    def _load_inbox_message_transaction_hashes(self, address: bytes, item_per_page: int, page_number: int) -> list:
        address_state = self._chain_manager.get_optimized_address_state(address)
        start_item_index = max(0, address_state.inbox_message_count() - item_per_page * page_number)
        end_item_index = min(address_state.inbox_message_count(), start_item_index + item_per_page)

        transaction_hashes = self._chain_manager.get_inbox_message_transaction_hashes(address,
                                                                                      start_item_index)
        actual_start_item_index = (start_item_index // config.dev.data_per_page) * config.dev.data_per_page
        inbox_message_transaction_hashes = transaction_hashes[start_item_index - actual_start_item_index:]
        while actual_start_item_index < end_item_index:
            actual_start_item_index += config.dev.data_per_page
            inbox_message_transaction_hashes.extend(self._chain_manager.get_inbox_message_transaction_hashes(address,
                                                                                                             actual_start_item_index))
        return inbox_message_transaction_hashes[:item_per_page][-1::-1]

    def get_mini_transactions_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page == 0:
            return None
        mini_transactions = []
        transaction_hashes = self._load_transaction_hashes(address, item_per_page, page_number)
        response = qrl_pb2.GetMiniTransactionsByAddressResp()
        for tx_hash in transaction_hashes:
            mini_transaction = qrl_pb2.MiniTransaction()
            mini_transaction.transaction_hash = bin2hstr(tx_hash)
            tx, _ = self._chain_manager.get_tx_metadata(tx_hash)
            amount = 0
            if tx.addr_from == address:
                amount -= tx.fee
            if isinstance(tx, TransferTransaction):
                if tx.addr_from == address:
                    amount -= tx.total_amount
                try:
                    for i in range(len(tx.addrs_to)):
                        if tx.addrs_to[i] == address:
                            amount += tx.amounts[i]
                except ValueError:
                    pass
            elif isinstance(tx, CoinBase):
                if tx.addr_to == address:
                    amount += tx.amount
            elif isinstance(tx, MultiSigSpend):
                try:
                    for i in range(len(tx.addrs_to)):
                        if tx.addrs_to[i] == address:
                            amount += tx.amounts[i]
                except ValueError:
                    pass

            if amount < 0:
                mini_transaction.out = True
            mini_transaction.amount = abs(amount)
            mini_transactions.append(mini_transaction)

        response.mini_transactions.extend(mini_transactions)
        response.balance = self._chain_manager.get_address_balance(address)
        return response

    def get_transactions_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page == 0:
            return None
        transaction_hashes = self._load_transaction_hashes(address,
                                                           item_per_page,
                                                           page_number)

        response = qrl_pb2.GetTransactionsByAddressResp()
        for tx_hash in transaction_hashes:
            tx, block_number = self._chain_manager.get_tx_metadata(tx_hash)
            b = self.get_block_from_index(block_number)
            transaction_detail = qrl_pb2.GetTransactionResp(tx=tx.pbdata,
                                                            confirmations=self.block_height - block_number + 1,
                                                            block_number=block_number,
                                                            block_header_hash=b.headerhash,
                                                            timestamp=b.timestamp,
                                                            addr_from=tx.addr_from)
            response.transactions_detail.extend([transaction_detail])

        return response

    def get_multi_sig_spend_txs_by_address(self,
                                           address: bytes,
                                           item_per_page: int,
                                           page_number: int,
                                           filter_type: int):
        # filter_type = 0 |  No Filter (default)
        # filter_type = 1 |  Executed Only (All executed are considered to be expired)
        # filter_type = 2 |  Non Executed
        # filter_type = 3 |  Expired
        # filter_type = 4 |  Non Expired
        # filter_type = 5 |  Non Executed & Expired
        # filter_type = 6 |  Non Executed & Non Expired

        if item_per_page == 0:
            return None

        transaction_hashes = self._load_multi_sig_spend_txn_hashes(address,
                                                                   item_per_page,
                                                                   page_number,
                                                                   filter_type)

        response = qrl_pb2.GetMultiSigSpendTxsByAddressResp()

        for tx_hash in transaction_hashes:
            if filter_type in (1, 2, 5, 6):
                vote_stats = self._chain_manager.get_vote_stats(tx_hash)
                if filter_type == 1 and not vote_stats.executed:
                    continue
                if filter_type in (2, 5, 6) and vote_stats.executed:
                    continue
            tx, block_number = self._chain_manager.get_tx_metadata(tx_hash)

            current_block_number = self._chain_manager.height

            is_expired = tx.expiry_block_number <= current_block_number
            if filter_type in (4, 6):
                if is_expired:
                    continue

            if filter_type in (3, 5):
                if not is_expired:
                    continue

            b = self.get_block_from_index(block_number)
            transaction_detail = qrl_pb2.GetTransactionResp(tx=tx.pbdata,
                                                            confirmations=self.block_height - block_number + 1,
                                                            block_number=block_number,
                                                            block_header_hash=b.headerhash,
                                                            timestamp=b.timestamp,
                                                            addr_from=tx.addr_from)
            response.transactions_detail.extend([transaction_detail])

        return response

    def get_vote_stats(self, multi_sig_spend_tx_hash: bytes):
        vote_stats = self._chain_manager.get_vote_stats(multi_sig_spend_tx_hash)
        return qrl_pb2.GetVoteStatsResp(vote_stats=vote_stats.pbdata)

    def get_inbox_messages_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page == 0:
            return None
        transaction_hashes = self._load_inbox_message_transaction_hashes(address,
                                                                         item_per_page,
                                                                         page_number)

        response = qrl_pb2.GetTransactionsByAddressResp()
        for tx_hash in transaction_hashes:
            tx, block_number = self._chain_manager.get_tx_metadata(tx_hash)
            b = self.get_block_from_index(block_number)
            transaction_detail = qrl_pb2.GetTransactionResp(tx=tx.pbdata,
                                                            confirmations=self.block_height - block_number + 1,
                                                            block_number=block_number,
                                                            block_header_hash=b.headerhash,
                                                            timestamp=b.timestamp,
                                                            addr_from=tx.addr_from)
            response.transactions_detail.extend([transaction_detail])

        return response

    def get_tokens_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page == 0:
            return None
        token_hashes = self._load_token_transaction_hashes(address, item_per_page, page_number)

        response = qrl_pb2.GetTokensByAddressResp()
        for tx_hash in token_hashes:
            tx, _ = self._chain_manager.get_tx_metadata(tx_hash)
            token_balance = self._chain_manager.get_token(address, tx.txhash)
            transaction_detail = qrl_pb2.TokenDetail(token_txhash=tx.txhash,
                                                     name=tx.name,
                                                     symbol=tx.symbol,
                                                     balance=token_balance.balance)
            response.tokens_detail.extend([transaction_detail])

        return response

    def get_slaves_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page > config.dev.data_per_page or item_per_page == 0:
            return None
        slave_hashes = self._load_slave_transaction_hashes(address, item_per_page, page_number)

        response = qrl_pb2.GetSlavesByAddressResp()
        for tx_hash in slave_hashes:
            tx, _ = self._chain_manager.get_tx_metadata(tx_hash)
            for index in range(0, len(tx.slave_pks)):
                transaction_detail = qrl_pb2.SlaveDetail(slave_address=bytes(QRLHelper.getAddress(tx.slave_pks[index])),
                                                         access_type=tx.access_types[index])
                response.slaves_detail.extend([transaction_detail])

        return response

    def get_lattice_pks_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page > config.dev.data_per_page or item_per_page == 0:
            return None
        lattice_pk_hashes = self._load_lattice_pks_transaction_hashes(address, item_per_page, page_number)

        response = qrl_pb2.GetLatticePKsByAddressResp()
        for tx_hash in lattice_pk_hashes:
            tx, _ = self._chain_manager.get_tx_metadata(tx_hash)
            transaction_detail = qrl_pb2.LatticePKsDetail(pk1=tx.pk1,
                                                          pk2=tx.pk2,
                                                          pk3=tx.pk3,
                                                          tx_hash=tx_hash)
            response.lattice_pks_detail.extend([transaction_detail])

        return response

    def get_multi_sig_addresses_by_address(self, address: bytes, item_per_page: int, page_number: int):
        if item_per_page > config.dev.data_per_page or item_per_page == 0:
            return None
        multi_sig_addresses = self._load_multi_sig_addresses(address,
                                                             item_per_page,
                                                             page_number)

        response = qrl_pb2.GetMultiSigAddressesByAddressResp()
        for multi_sig_address in multi_sig_addresses:
            multi_sig_detail = qrl_pb2.MultiSigDetail(
                address=multi_sig_address,
                balance=self._chain_manager.get_multi_sig_address_state(multi_sig_address).balance,
            )
            response.multi_sig_detail.extend([multi_sig_detail])

        return response

    def get_transaction(self, query_hash: bytes):
        """
        This method returns an object that matches the query hash
        """
        # FIXME: At some point, all objects in DB will indexed by a hash
        # TODO: Search tx hash
        # FIXME: We dont need searches, etc.. getting a protobuf indexed by hash from DB should be enough
        # FIXME: This is just a workaround to provide functionality
        result = self._chain_manager.get_tx_metadata(query_hash)
        return result

    def get_block_header_hash_by_number(self, query_block_number: int):
        return self._chain_manager.get_block_header_hash_by_number(query_block_number)

    def get_unconfirmed_transaction(self, query_hash: bytes):
        result = self._chain_manager.get_unconfirmed_transaction(query_hash)
        return result

    def get_block_last(self) -> Optional[Block]:
        """
        This method returns an object that matches the query hash
        """
        return self._chain_manager.last_block

    def get_block_from_hash(self, query_hash: bytes) -> Optional[Block]:
        """
        This method returns an object that matches the query hash
        """
        return self._chain_manager.get_block(query_hash)

    def get_block_from_index(self, index: int) -> Block:
        """
        This method returns an object that matches the query hash
        """
        return self._chain_manager.get_block_by_number(index)

    def get_blockidx_from_txhash(self, transaction_hash):
        result = self._chain_manager.get_tx_metadata(transaction_hash)
        if result:
            return result[1]
        return None

    def get_latest_blocks(self, offset, count) -> List[Block]:
        answer = []
        end = self.block_height - offset
        start = max(0, end - count + 1)
        for blk_idx in range(start, end + 1):
            answer.append(self._chain_manager.get_block_by_number(blk_idx))

        return answer

    def get_latest_transactions(self, offset, count):
        answer = []
        skipped = 0
        for tx in self._chain_manager.get_last_transactions():
            if skipped >= offset:
                answer.append(tx)
                if len(answer) >= count:
                    break
            else:
                skipped += 1

        return answer

    def get_latest_transactions_unconfirmed(self, offset, count):
        answer = []
        skipped = 0
        for tx_set in self._chain_manager.tx_pool.transactions:
            if skipped >= offset:
                answer.append(tx_set[1])
                if len(answer) >= count:
                    break
            else:
                skipped += 1
        return answer

    def get_node_info(self) -> qrl_pb2.NodeInfo:
        info = qrl_pb2.NodeInfo()
        info.version = self.version
        info.state = self.state
        info.num_connections = self.num_connections
        info.num_known_peers = self.num_known_peers
        info.uptime = self.uptime
        info.block_height = self.block_height
        info.block_last_hash = self._chain_manager.last_block.headerhash
        info.network_id = config.user.genesis_prev_headerhash
        return info

    def get_block_timeseries(self, block_count) -> Iterator[qrl_pb2.BlockDataPoint]:
        result = []

        if self.block_height <= 0:
            return result

        block = self._chain_manager.last_block
        if block is None:
            return result

        headerhash_current = block.headerhash
        while len(result) < block_count:
            data_point = self._chain_manager.get_block_datapoint(headerhash_current)

            if data_point is None:
                break

            result.append(data_point)
            headerhash_current = data_point.header_hash_prev

        return reversed(result)

    def get_blockheader_and_metadata(self, block_number=0) -> Tuple:
        return self._chain_manager.get_blockheader_and_metadata(block_number)

    def get_block_to_mine(self, wallet_address) -> list:
        return self._chain_manager.get_block_to_mine(self._pow.miner, wallet_address)

    def submit_mined_block(self, blob) -> bool:
        return self._pow.miner.submit_mined_block(blob)
