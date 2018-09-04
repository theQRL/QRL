# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from decimal import Decimal
from typing import Optional, List, Iterator, Tuple

from pyqrllib.pyqrllib import QRLHelper, bin2hstr
from twisted.internet import reactor

from qrl.core import config
from qrl.core.AddressState import AddressState
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
        self.peer_manager.register(P2PPeerManager.EventType.NO_PEERS, self.connect_peers)

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
            return config.dev.mining_setpoint_blocktime

        movavg = self._chain_manager.get_measurement(block.timestamp,
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

    def connect_peers(self):
        self.peer_manager.connect_peers()

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

        self.peer_manager._p2pfactory = self._p2pfactory
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
    def create_message_txn(message_hash: bytes,
                           fee: int,
                           xmss_pk: bytes,
                           master_addr: bytes):
        return MessageTransaction.create(message_hash=message_hash,
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
                       fee: int,
                       xmss_pk: bytes,
                       master_addr: bytes) -> TransferTransaction:
        addr_from = self.get_addr_from(xmss_pk, master_addr)
        balance = self._chain_manager.get_address_balance(addr_from)
        if sum(amounts) + fee > balance:
            raise ValueError("Not enough funds in the source address")

        return TransferTransaction.create(addrs_to=addrs_to,
                                          amounts=amounts,
                                          fee=fee,
                                          xmss_pk=xmss_pk,
                                          master_addr=master_addr)

    def create_slave_tx(self,
                        slave_pks: list,
                        access_types: list,
                        fee: int,
                        xmss_pk: bytes,
                        master_addr: bytes) -> SlaveTransaction:
        return SlaveTransaction.create(slave_pks=slave_pks,
                                       access_types=access_types,
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
        if not AddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        return self._chain_manager.get_address_is_used(address)

    def get_address_state(self, address: bytes) -> AddressState:
        if address != config.dev.coinbase_address and not AddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        address_state = self._chain_manager.get_address_state(address)

        return address_state

    def get_all_address_state(self) -> list:
        return self._chain_manager.get_all_address_state()

    def get_transactions_by_address(self, address: bytes):
        address_state = self._chain_manager.get_address_state(address)
        mini_transactions = []
        balance = 0
        for tx_hash in address_state.transaction_hashes:
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

            if amount < 0:
                mini_transaction.out = True
            mini_transaction.amount = abs(amount)
            mini_transactions.append(mini_transaction)
            balance += amount

        return mini_transactions, balance

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
