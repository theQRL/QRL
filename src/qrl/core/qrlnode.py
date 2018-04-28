# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
import time
from decimal import Decimal
from typing import Optional, List, Iterator

from twisted.internet import reactor

from pyqrllib.pyqrllib import QRLHelper

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.ESyncState import ESyncState
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.State import State
from qrl.core.TokenList import TokenList
from qrl.core.Transaction import TransferTransaction, TransferTokenTransaction, TokenTransaction, SlaveTransaction, \
    LatticePublicKey
from qrl.core.misc import ntp
from qrl.core.misc.expiring_set import ExpiringSet
from qrl.core.misc.logger import logger
from qrl.core.node import POW, SyncState
from qrl.core.p2p.p2pChainManager import P2PChainManager
from qrl.core.p2p.p2pPeerManager import P2PPeerManager
from qrl.core.p2p.p2pTxManagement import P2PTxManagement
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.generated import qrl_pb2


class QRLNode:
    def __init__(self, db_state: State, mining_address: bytes):
        self.start_time = time.time()
        self.db_state = db_state
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

        banned_peers_filename = os.path.join(config.user.wallet_dir, config.dev.banned_peers_filename)
        self._banned_peers = ExpiringSet(expiration_time=config.user.ban_minutes * 60,
                                         filename=banned_peers_filename)

        reactor.callLater(10, self.monitor_chain_state)

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    @property
    def version(self):
        # FIXME: Move to __version__ coming from pip
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
        # FIXME
        return self._p2pfactory.connections

    @property
    def num_known_peers(self):
        # FIXME
        return len(self.peer_addresses)

    @property
    def uptime(self):
        return int(time.time() - self.start_time)

    @property
    def block_height(self):
        return self._chain_manager.height

    @property
    def epoch(self):
        if not self._chain_manager.get_last_block():
            return 0
        return self._chain_manager.get_last_block().block_number // config.dev.blocks_per_epoch

    @property
    def uptime_network(self):
        block_one = self._chain_manager.get_block_by_number(1)
        network_uptime = 0
        if block_one:
            network_uptime = int(time.time() - block_one.timestamp)
        return network_uptime

    @property
    def block_last_reward(self):
        if not self._chain_manager.get_last_block():
            return 0

        return self._chain_manager.get_last_block().block_reward

    @property
    def block_time_mean(self):
        block = self._chain_manager.get_last_block()

        prev_block_metadata = self._chain_manager.state.get_block_metadata(block.prev_headerhash)
        if prev_block_metadata is None:
            return config.dev.mining_setpoint_blocktime

        movavg = self._chain_manager.state.get_measurement(block.timestamp,
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
        return self.db_state.total_coin_supply()

    @property
    def coin_supply_max(self):
        # FIXME: Keep a moving var
        return config.dev.max_coin_supply

    @property
    def peer_addresses(self):
        return self.peer_manager.peer_addresses

    def get_peers_stat(self) -> list:
        peers_stat = []
        for source in self.peer_manager.peer_node_status:
            peer_stat = qrl_pb2.PeerStat(peer_ip=source.peer_ip,
                                         peer_port=source.peer_port,
                                         node_chain_state=self.peer_manager.peer_node_status[source])
            peers_stat.append(peer_stat)
        return peers_stat

    ####################################################
    ####################################################
    ####################################################
    ####################################################
    def is_banned(self, addr_remote: str):
        return addr_remote in self._banned_peers

    def ban_peer(self, peer_obj):
        self._banned_peers.add(peer_obj.addr_remote)
        logger.warning('Banned %s', peer_obj.addr_remote)
        peer_obj.loseConnection()

    def connect_peers(self):
        logger.info('<<<Reconnecting to peer list: %s', self.peer_addresses)
        for peer_address in self.peer_addresses:
            if self.is_banned(peer_address):
                continue
            self._p2pfactory.connect_peer(peer_address)

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def monitor_chain_state(self):
        self.peer_manager.monitor_chain_state()

        last_block = self._chain_manager.get_last_block()
        block_metadata = self.db_state.get_block_metadata(last_block.headerhash)
        node_chain_state = qrl_pb2.NodeChainState(block_number=last_block.block_number,
                                                  header_hash=last_block.headerhash,
                                                  cumulative_difficulty=bytes(block_metadata.cumulative_difficulty),
                                                  timestamp=int(time.time()))

        self.peer_manager.broadcast_chain_state(node_chain_state=node_chain_state)
        channel = self.peer_manager.get_better_difficulty(block_metadata.cumulative_difficulty)
        logger.debug('Got better difficulty %s', channel)
        if channel:
            logger.debug('Connection id >> %s', channel.addr_remote)
            channel.get_headerhash_list(self._chain_manager.height)
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
        balance = self.db_state.balance(addr_from)
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

    def create_lattice_public_key_txn(self,
                                      kyber_pk: bytes,
                                      dilithium_pk: bytes,
                                      fee: int,
                                      xmss_pk: bytes,
                                      master_addr: bytes) -> SlaveTransaction:
        return LatticePublicKey.create(kyber_pk=kyber_pk,
                                       dilithium_pk=dilithium_pk,
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

        return self.db_state.address_used(address)

    def get_address_state(self, address: bytes) -> qrl_pb2.AddressState:
        if not AddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        address_state = self.db_state.get_address_state(address)

        return address_state

    def get_transaction(self, query_hash: bytes):
        """
        This method returns an object that matches the query hash
        """
        # FIXME: At some point, all objects in DB will indexed by a hash
        # TODO: Search tx hash
        # FIXME: We dont need searches, etc.. getting a protobuf indexed by hash from DB should be enough
        # FIXME: This is just a workaround to provide functionality
        result = self._chain_manager.get_transaction(query_hash)
        if result:
            return result[0], result[1]
        return None, None

    def get_block_last(self) -> Optional[Block]:
        """
        This method returns an object that matches the query hash
        """
        return self._chain_manager.get_last_block()

    def get_block_from_hash(self, query_hash: bytes) -> Optional[Block]:
        """
        This method returns an object that matches the query hash
        """
        return self.db_state.get_block(query_hash)

    def get_block_from_index(self, index: int) -> Block:
        """
        This method returns an object that matches the query hash
        """
        return self.db_state.get_block_by_number(index)

    def get_blockidx_from_txhash(self, transaction_hash):
        result = self.db_state.get_tx_metadata(transaction_hash)
        if result:
            return result[1]
        return None

    def get_token_detailed_list(self):
        pbdata = self.db_state.get_token_list()
        token_list = TokenList.from_json(pbdata)
        token_detailed_list = qrl_pb2.TokenDetailedList()
        for token_txhash in token_list.token_txhash:
            token_txn, _ = self.db_state.get_tx_metadata(token_txhash)
            transaction_extended = qrl_pb2.TransactionExtended(tx=token_txn.pbdata,
                                                               addr_from=token_txhash.addr_from)
            token_detailed_list.extended_tokens.extend([transaction_extended])
        return token_detailed_list

    def get_latest_blocks(self, offset, count) -> List[Block]:
        answer = []
        end = self.block_height - offset
        start = max(0, end - count - offset)
        for blk_idx in range(start, end + 1):
            answer.append(self._chain_manager.get_block_by_number(blk_idx))

        return answer

    def get_latest_transactions(self, offset, count):
        answer = []
        skipped = 0
        for tx in self.db_state.get_last_txs():
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
                answer.append(tx_set[1].transaction)
                if len(answer) >= count:
                    break
            else:
                skipped += 1
        return answer

    def getNodeInfo(self) -> qrl_pb2.NodeInfo:
        info = qrl_pb2.NodeInfo()
        info.version = self.version
        info.state = self.state
        info.num_connections = self.num_connections
        info.num_known_peers = self.num_known_peers
        info.uptime = self.uptime
        info.block_height = self.block_height
        info.block_last_hash = self._chain_manager.get_last_block().headerhash  # FIXME
        info.network_id = config.dev.genesis_prev_headerhash  # FIXME
        return info

    def get_block_timeseries(self, block_count) -> Iterator[qrl_pb2.BlockDataPoint]:
        result = []

        if self._chain_manager.height == 0:
            return result

        block = self._chain_manager.get_last_block()
        if block is None:
            return result

        headerhash_current = block.headerhash
        while len(result) < block_count:
            data_point = self._chain_manager.state.get_block_datapoint(headerhash_current)

            if data_point is None:
                break

            result.append(data_point)
            headerhash_current = data_point.header_hash_prev

        return reversed(result)

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def broadcast_ephemeral_message(self, encrypted_ephemeral: EncryptedEphemeralMessage) -> bool:
        if not encrypted_ephemeral.validate():
            return False

        self._p2pfactory.broadcast_ephemeral_message(encrypted_ephemeral)

        return True

    def collect_ephemeral_message(self, msg_id):
        return self.db_state.get_ephemeral_metadata(msg_id)

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def get_blockheader_and_metadata(self, block_number) -> list:
        if block_number == 0:
            block_number = self.block_height

        result = []
        block = self.get_block_from_index(block_number)
        if block:
            blockheader = block.blockheader
            blockmetadata = self.db_state.get_block_metadata(blockheader.headerhash)
            result = [blockheader, blockmetadata]

        return result

    def get_block_to_mine(self, wallet_address) -> list:
        last_block = self._chain_manager.get_last_block()
        last_block_metadata = self._chain_manager.state.get_block_metadata(last_block.headerhash)
        return self._pow.miner.get_block_to_mine(wallet_address,
                                                 self._chain_manager.tx_pool,
                                                 last_block,
                                                 last_block_metadata.block_difficulty)

    def submit_mined_block(self, blob) -> bool:
        return self._pow.miner.submit_mined_block(blob)
