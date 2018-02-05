# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import time
import os
import simplejson as json
from decimal import Decimal
from typing import Optional, List

from twisted.internet import reactor

from qrl.core.p2pfactory import P2PFactory
from qrl.core.node import POW, SyncState
from qrl.core import config
from qrl.core.misc import ntp
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.Block import Block
from qrl.core.ESyncState import ESyncState
from qrl.core.State import State
from qrl.core.AddressState import AddressState
from qrl.core.TokenList import TokenList
from qrl.core.Transaction import TransferTransaction, TransferTokenTransaction, TokenTransaction, SlaveTransaction
from qrl.core.misc.logger import logger
from qrl.core.p2pChainManager import P2PChainManager
from qrl.core.ChainManager import ChainManager
from qrl.core.p2pPeerManager import P2PPeerManager
from qrl.core.p2pTxManagement import P2PTxManagement
from qrl.generated import qrl_pb2


class QRLNode:
    def __init__(self, db_state: State, slaves: list):
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

        self.slaves = slaves

        self.banned_peers_filename = os.path.join(config.user.wallet_dir, config.dev.banned_peers_filename)

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
        # FIXME: Keep a moving mean
        return 0

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
        return self.peer_manager._peer_addresses

    ####################################################
    ####################################################
    ####################################################
    ####################################################
    def _update_banned_peers(self, banned_peers):
        current_time = ntp.getTime()
        ip_list = list(banned_peers.keys())

        for ip in ip_list:
            if current_time > banned_peers[ip]:
                del banned_peers[ip]

        self._put_banned_peers(banned_peers)

    def _put_banned_peers(self, banned_peers: dict):
        with open(self.banned_peers_filename, 'w') as f:
            json.dump(banned_peers, f)

    def _get_banned_peers(self) -> dict:
        try:
            with open(self.banned_peers_filename, 'r') as f:
                banned_peers = json.load(f)
        except FileNotFoundError:
            banned_peers = dict()
            self._put_banned_peers(banned_peers)

        return banned_peers

    def is_banned(self, peer_ip: str):
        banned_peers = self._get_banned_peers()
        self._update_banned_peers(banned_peers)

        if peer_ip in banned_peers:
            return True

    def ban_peer(self, peer_obj):
        ip = peer_obj.peer_ip
        ban_time = ntp.getTime() + (config.user.ban_minutes * 60)
        banned_peers = self._get_banned_peers()
        banned_peers[ip] = ban_time

        self._update_banned_peers(banned_peers)
        logger.warning('Banned %s', peer_obj.peer_ip)
        peer_obj.loseConnection()

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
            logger.debug('Connection id >> %s', channel.connection_id)
            channel.get_headerhash_list(self._chain_manager.height)
        reactor.callLater(config.user.chain_state_broadcast_period, self.monitor_chain_state)

    # FIXME: REMOVE. This is temporary
    def set_chain(self, chain_manager: ChainManager):
        self._chain_manager = chain_manager

    ####################################################
    ####################################################
    ####################################################
    ####################################################

    def connect_peers(self):
        logger.info('<<<Reconnecting to peer list: %s', self.peer_addresses)
        for peer_address in self.peer_addresses:
            if self.is_banned(peer_address):
                continue
            self._p2pfactory.connect_peer(peer_address)

    def start_pow(self, mining_thread_count):
        # FIXME: This seems an unexpected side effect. It should be refactored
        self._pow = POW(chain_manager=self._chain_manager,
                        p2p_factory=self._p2pfactory,
                        sync_state=self._sync_state,
                        time_provider=ntp,
                        slaves=self.slaves,
                        mining_thread_count=mining_thread_count)

        self._pow.start()

    def start_listening(self):
        self._p2pfactory = P2PFactory(chain_manager=self._chain_manager,
                                      sync_state=self.sync_state,
                                      qrl_node=self)  # FIXME: Try to avoid cycle references

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

    def get_address_bundle(self, key_addr: bytes):
        for addr in self._chain_manager.wallet.address_bundle:
            if addr.address == key_addr:
                return addr
        return None

    # FIXME: Rename this appropriately
    def transfer_coins(self, addr_from: bytes, addr_to: bytes, amount: int, xmss_ots_index: int, fee: int = 0):
        addr_bundle = self.get_address_bundle(addr_from)
        if addr_bundle is None:
            raise LookupError("The source address does not belong to this wallet/node")

        xmss_from = addr_bundle.xmss
        if xmss_from is None:
            raise LookupError("The source address does not belong to this wallet/node")

        xmss_pk = xmss_from.pk()

        # TODO: Review this
        # Balance validation
        if xmss_from.get_remaining_signatures() == 1:
            balance = self.db_state.balance(addr_from)
            if amount + fee < balance:
                # FIXME: maybe this is too strict?
                raise RuntimeError("Last signature! You must move all the funds to another account!")

        tx = self.create_send_tx(addr_from,
                                 addr_to,
                                 amount,
                                 fee,
                                 xmss_pk,
                                 xmss_ots_index)

        tx.sign(xmss_from)
        self.submit_send_tx(tx)
        return tx

    @staticmethod
    def create_token_txn(addr_from: bytes,
                         symbol: bytes,
                         name: bytes,
                         owner: bytes,
                         decimals: int,
                         initial_balances,
                         fee: int,
                         xmss_pk: bytes,
                         xmss_ots_index: int):
        return TokenTransaction.create(addr_from,
                                       symbol,
                                       name,
                                       owner,
                                       decimals,
                                       initial_balances,
                                       fee,
                                       xmss_pk,
                                       xmss_ots_index)

    @staticmethod
    def create_transfer_token_txn(addr_from: bytes,
                                  addr_to: bytes,
                                  token_txhash: bytes,
                                  amount: int,
                                  fee: int,
                                  xmss_pk: bytes,
                                  xmss_ots_index: int):
        return TransferTokenTransaction.create(addr_from,
                                               token_txhash,
                                               addr_to,
                                               amount,
                                               fee,
                                               xmss_pk,
                                               xmss_ots_index)

    # FIXME: Rename this appropriately
    def create_send_tx(self,
                       addr_from: bytes,
                       addr_to: bytes,
                       amount: int,
                       fee: int,
                       xmss_pk: bytes,
                       xmss_ots_index: int) -> TransferTransaction:
        balance = self.db_state.balance(addr_from)
        if amount + fee > balance:
            raise RuntimeError("Not enough funds in the source address")

        return TransferTransaction.create(addr_from=addr_from,
                                          addr_to=addr_to,
                                          amount=amount,
                                          fee=fee,
                                          xmss_pk=xmss_pk,
                                          xmss_ots_index=xmss_ots_index)

    def create_slave_tx(self,
                        addr_from: bytes,
                        slave_pks: list,
                        access_types: list,
                        fee: int,
                        xmss_pk: bytes,
                        xmss_ots_index: int) -> SlaveTransaction:
        return SlaveTransaction.create(addr_from=addr_from,
                                       slave_pks=slave_pks,
                                       access_types=access_types,
                                       fee=fee,
                                       xmss_pk=xmss_pk,
                                       xmss_ots_index=xmss_ots_index)

    # FIXME: Rename this appropriately
    def submit_send_tx(self, tx) -> bool:
        if tx is None:
            raise ValueError("The transaction was empty")

        if self._chain_manager.tx_pool.is_full_transaction_pool():
            raise ValueError("Transaction Pool is full")

        if tx.subtype in (qrl_pb2.Transaction.TRANSFER,
                          qrl_pb2.Transaction.LATTICE,
                          qrl_pb2.Transaction.MESSAGE,
                          qrl_pb2.Transaction.TOKEN,
                          qrl_pb2.Transaction.TRANSFERTOKEN,
                          qrl_pb2.Transaction.SLAVE):
            self._p2pfactory.add_unprocessed_txn(tx, ip=None)  # TODO (cyyber): Replace None with IP made API request

        return True

    def get_address_is_used(self, address: bytes) -> bool:
        if not AddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        return self.db_state.address_used(address)

    def get_address_state(self, address: bytes) -> qrl_pb2.AddressState:
        if not AddressState.address_is_valid(address):
            raise ValueError("Invalid Address")

        address_state = self.db_state.get_address(address)

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
            token_detailed_list.tokens.extend([token_txn.pbdata])
        return token_detailed_list

    def get_latest_blocks(self, offset, count) -> List[Block]:
        answer = []
        end = self.block_height - offset
        start = max(0, end - count - offset)
        for blk_idx in range(start, end + 1):
            answer.append(self._chain_manager.get_block_by_number(blk_idx))

        return answer

    def get_latest_transactions(self, offset, count):
        # FIXME: This is incorrect
        # FIXME: Moved code. Breaking encapsulation. Refactor
        answer = []
        skipped = 0
        for tx in self.db_state.get_last_txs():
            if isinstance(tx, TransferTransaction):
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
        for tx in self._chain_manager.tx_pool.transaction_pool:
            if isinstance(tx, TransferTransaction):
                if skipped >= offset:
                    answer.append(tx)
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
        info.block_last_hash = b''  # FIXME
        info.network_id = config.dev.genesis_prev_headerhash  # FIXME
        return info

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
        self._chain_manager.collect_ephemeral_message(msg_id)
