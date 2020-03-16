# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import random

from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import UInt256ToString
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.ESyncState import ESyncState
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.misc import ntp, logger
from qrl.core.node import SyncState
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.core.p2p.IPMetadata import IPMetadata
from qrl.core.processors.TxnProcessor import TxnProcessor
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.LatticeTransaction import LatticeTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.multisig.MultiSigCreate import MultiSigCreate
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from qrl.generated import qrllegacy_pb2, qrl_pb2

p2p_msg_priority = {
            qrllegacy_pb2.LegacyMessage.VE: 0,
            qrllegacy_pb2.LegacyMessage.PL: 0,
            qrllegacy_pb2.LegacyMessage.PONG: 0,

            ######################
            qrllegacy_pb2.LegacyMessage.MR: 2,
            qrllegacy_pb2.LegacyMessage.SFM: 1,

            qrllegacy_pb2.LegacyMessage.BK: 1,
            qrllegacy_pb2.LegacyMessage.FB: 0,
            qrllegacy_pb2.LegacyMessage.PB: 0,
            qrllegacy_pb2.LegacyMessage.BH: 1,

            ############################
            qrllegacy_pb2.LegacyMessage.TX: 1,
            qrllegacy_pb2.LegacyMessage.MT: 1,
            qrllegacy_pb2.LegacyMessage.TK: 1,
            qrllegacy_pb2.LegacyMessage.TT: 1,
            qrllegacy_pb2.LegacyMessage.LT: 1,
            qrllegacy_pb2.LegacyMessage.SL: 1,

            qrllegacy_pb2.LegacyMessage.EPH: 3,

            qrllegacy_pb2.LegacyMessage.SYNC: 0,
            qrllegacy_pb2.LegacyMessage.CHAINSTATE: 0,
            qrllegacy_pb2.LegacyMessage.HEADERHASHES: 1,
            qrllegacy_pb2.LegacyMessage.P2P_ACK: 0,

            qrllegacy_pb2.LegacyMessage.MC: 1,
            qrllegacy_pb2.LegacyMessage.MS: 1,
            qrllegacy_pb2.LegacyMessage.MV: 1,
        }


class P2PFactory(ServerFactory):
    protocol = P2PProtocol

    def __init__(self,
                 chain_manager: ChainManager,
                 sync_state: SyncState,
                 qrl_node):

        self.master_mr = MessageReceipt()
        self.pow = None
        self.sync_state = sync_state

        self._ntp = ntp
        self._qrl_node = qrl_node
        self._chain_manager = chain_manager
        self._chain_manager.set_broadcast_tx(self.broadcast_tx)

        self._syncing_enabled = False
        self._target_channel = None
        self._target_node_header_hash = None
        self._last_requested_block_number = None

        self._genesis_processed = False
        self._peer_connections = []
        self._txn_processor_running = False

        self.peer_blockheight = dict()

        reactor.callLater(config.user.monitor_connections_interval,
                          self.monitor_connections)

        self.p2p_msg_priority = p2p_msg_priority

        # Maintains the list of ips in the queue that can be tried to form a new p2p connection
        self._peer_q = []

    def add_new_peers_to_peer_q(self, peer_list):
        """
        Checks ip must not already be in the _peer_q and
        connection has not already been established from that ip and port
        before adding the new set of peer into _peer_q
        """
        peer_set = set(peer_list)
        for peer_conn in self._peer_connections:
            ip_port = peer_conn.peer.full_address
            if ip_port in peer_set:
                peer_set.remove(ip_port)

        for ip_port in self._peer_q:
            if ip_port in peer_set:
                peer_set.remove(ip_port)

        self._peer_q.extend(peer_set)

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def get_random_peer(self):
        # FIXME: Used a named tuple to improve readability?
        # FIXME: This probably can go the peerManager
        max_cumulative_difficulty = 0
        for addr_remote in self.peer_blockheight:
            max_cumulative_difficulty = max(max_cumulative_difficulty, self.peer_blockheight[addr_remote][2])

        best_connection_ids = []
        for addr_remote in self.peer_blockheight:
            if self.peer_blockheight[addr_remote][2] == max_cumulative_difficulty:
                best_connection_ids.append(addr_remote)

        selected_peer_connections = []
        for addr_remote in best_connection_ids:
            for peer_conn in self._peer_connections:
                if peer_conn.peer.full_address == addr_remote:
                    selected_peer_connections.append(peer_conn)

        if len(selected_peer_connections) == 0 or max_cumulative_difficulty == 0:
            return None

        return random.sample(selected_peer_connections, 1)[0]

    def update_peer_blockheight(self, addr_remote, block_number, headerhash, cumulative_difficulty):
        # FIXME: Use a named tuple to improve readability?
        self.peer_blockheight[addr_remote] = [block_number, headerhash, int(UInt256ToString(cumulative_difficulty))]

    def request_peer_blockheight(self):
        for peer in self._peer_connections:
            msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.BH,
                                              bhData=qrl_pb2.BlockHeightData(block_number=0))
            peer.send(msg)

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################

    @property
    def num_connections(self):
        return len(self._peer_connections)

    @property
    def connections(self):
        return list(self._peer_connections)

    @property
    def synced(self):
        return self.pow.sync_state.state == ESyncState.synced

    @property
    def reached_conn_limit(self):
        return len(self._peer_connections) >= config.user.max_peers_limit

    def get_connected_peer_addrs(self):
        return set([peer.peer.full_address for peer in self._peer_connections])

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################

    @property
    def chain_height(self):
        return self._chain_manager.height

    def get_last_block(self):
        return self._chain_manager.last_block

    def get_headerhashes(self, start_blocknumber):
        return self._chain_manager.get_headerhashes(start_blocknumber)

    def get_cumulative_difficulty(self):
        return self._chain_manager.get_cumulative_difficulty()

    def get_block_by_number(self, block_number):
        return self._chain_manager.get_block_by_number(block_number)

    def is_block_present(self, header_hash: bytes) -> bool:
        if not self._chain_manager.get_block(header_hash):
            if header_hash not in self.pow.future_blocks:
                return False

        return True

    def block_received(self, source, block: Block):
        self.pow.last_pb_time = ntp.getTime()
        logger.info('>>> Received Block #%d %s', block.block_number, bin2hstr(block.headerhash))

        if source != self._target_channel:
            if self._target_channel is None:
                logger.warning('Received block and target channel is None')
            else:
                logger.warning('Received block from unexpected peer')
                logger.warning('Expected peer: %s', self._target_channel.peer)
                logger.warning('Found peer: %s', source.peer)
            return

        if block.block_number != self._last_requested_block_number:
            logger.warning('Did not match %s', self._last_requested_block_number)
            self._qrl_node.peer_manager.ban_channel(source)
            return

        target_start_blocknumber = self._target_node_header_hash.block_number
        expected_headerhash = self._target_node_header_hash.headerhashes[block.block_number - target_start_blocknumber]
        if block.headerhash != expected_headerhash:
            logger.warning('Did not match headerhash')
            logger.warning('Expected headerhash %s', expected_headerhash)
            logger.warning('Found headerhash %s', block.headerhash)
            self._qrl_node.peer_manager.ban_channel(source)
            return

        if not block.validate(self._chain_manager, self.pow.future_blocks):
            logger.warning('Syncing Failed: Block Validation Failed')
            self._qrl_node.peer_manager.ban_channel(source)
            return

        if self._chain_manager.add_block(block, check_stale=False):
            if self._chain_manager.last_block.headerhash == block.headerhash:
                self.pow.suspend_mining_timestamp = ntp.getTime() + config.dev.sync_delay_mining
        else:
            logger.warning('Failed to Add Block')
            self._qrl_node.peer_manager.ban_channel(source)
            return

        try:
            reactor.download_monitor.cancel()
        except Exception as e:
            logger.warning("PB: %s", e)

        if self.is_syncing_finished():
            return

        self._last_requested_block_number += 1

        self.peer_fetch_block()

    def is_syncing(self) -> bool:
        return self._syncing_enabled

    def is_syncing_finished(self, force_finish=False):
        curr_index = self._last_requested_block_number - self._target_node_header_hash.block_number + 1
        if curr_index == len(self._target_node_header_hash.headerhashes) or force_finish:
            self._last_requested_block_number = None
            self._target_node_header_hash = None
            self._target_channel = None
            self._syncing_enabled = False
            return True

        return False

    def peer_fetch_block(self, retry=0):
        node_header_hash = self._target_node_header_hash
        curr_index = self._last_requested_block_number - node_header_hash.block_number

        block_headerhash = node_header_hash.headerhashes[curr_index]
        block = self._chain_manager.get_block(block_headerhash)

        if retry >= 1:
            logger.debug('Retry Limit Hit')
            self._qrl_node.peer_manager.ban_channel(self._target_channel)
            self.is_syncing_finished(force_finish=True)
            return

        while block and curr_index + 1 < len(node_header_hash.headerhashes):
            self._last_requested_block_number += 1
            curr_index = self._last_requested_block_number - node_header_hash.block_number
            block_headerhash = node_header_hash.headerhashes[curr_index]
            block = self._chain_manager.get_block(block_headerhash)

        if block and self.is_syncing_finished():
            return

        self._target_channel.send_fetch_block(self._last_requested_block_number)
        reactor.download_monitor = reactor.callLater(100, self.peer_fetch_block, retry + 1)

    def compare_and_sync(self, source_peer, node_header_hash: qrl_pb2.NodeHeaderHash):
        if self._syncing_enabled:
            logger.info('>> Ignoring compare_and_sync Syncing Enabled')
            return
        last_block = self.get_last_block()
        node_last_block_number = node_header_hash.block_number + len(node_header_hash.headerhashes) - 1
        last_block_number = min(last_block.block_number, node_last_block_number)
        if last_block_number < node_header_hash.block_number:
            return
        fork_block_number = last_block.block_number + 1
        fork_found = False
        for i in range(last_block_number, node_header_hash.block_number - 1, -1):
            block = self._chain_manager.get_block_by_number(i)
            if block:
                if block.headerhash == node_header_hash.headerhashes[i - node_header_hash.block_number]:
                    break
            fork_block_number = i
            fork_found = True

        if fork_found or (last_block.block_number < node_last_block_number):
            self._target_channel = source_peer
            self._target_node_header_hash = node_header_hash
            self._last_requested_block_number = fork_block_number
            self._syncing_enabled = True
            self.peer_fetch_block()

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def request_full_message(self, mr_data: qrllegacy_pb2.MRData):
        """
        Request Full Message
        This function request for the full message against,
        the Message Receipt received.
        :return:
        """

        # FIXME: Again, breaking encasulation
        # FIXME: Huge amount of lookups in dictionaries
        msg_hash = mr_data.hash

        if msg_hash in self.master_mr._hash_msg:
            if msg_hash in self.master_mr.requested_hash:
                del self.master_mr.requested_hash[msg_hash]
            return

        if msg_hash not in self.master_mr.requested_hash:
            return

        peers_list = self.master_mr.requested_hash[msg_hash].peers_connection_list
        message_request = self.master_mr.requested_hash[msg_hash]
        for peer in peers_list:
            if peer in message_request.already_requested_peers:
                continue
            message_request.already_requested_peers.append(peer)

            msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SFM,
                                              mrData=qrllegacy_pb2.MRData(hash=mr_data.hash, type=mr_data.type))

            peer.send(msg)

            call_later_obj = reactor.callLater(config.dev.message_receipt_timeout,
                                               self.request_full_message,
                                               mr_data)

            message_request.callLater = call_later_obj
            return

        # If execution reach to this line, then it means no peer was able to provide
        # Full message for this hash thus the hash has to be deleted.
        # Moreover, negative points could be added to the peers, for this behavior
        if msg_hash in self.master_mr.requested_hash:
            del self.master_mr.requested_hash[msg_hash]

    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def reset_processor_flag(self, _):
        self._txn_processor_running = False

    def reset_processor_flag_with_err(self, msg):
        logger.error('Exception in txn task')
        logger.error('%s', msg)
        self._txn_processor_running = False

    def add_unprocessed_txn(self, tx, ip) -> bool:
        if tx.fee < config.user.transaction_minimum_fee:
            logger.info("Dropping Txn %s", bin2hstr(tx.txhash))
            logger.info("Reason: Fee %s is below threshold fee %s", tx.fee, config.user.transaction_minimum_fee)
            return False

        if not self._chain_manager.tx_pool.update_pending_tx_pool(tx, ip):
            return False

        if not self._txn_processor_running:
            txn_processor = TxnProcessor(chain_manager=self._chain_manager,
                                         transaction_pool_obj=self._chain_manager.tx_pool,
                                         broadcast_tx=self.broadcast_tx)

            task_defer = TxnProcessor.create_cooperate(txn_processor).whenDone()
            task_defer.addCallback(self.reset_processor_flag) \
                .addErrback(self.reset_processor_flag_with_err)
            self._txn_processor_running = True

        return True

    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def broadcast_tx(self, tx: TransferTransaction):
        logger.info('<<<Transmitting TX: %s', bin2hstr(tx.txhash))

        if isinstance(tx, MessageTransaction):
            legacy_type = qrllegacy_pb2.LegacyMessage.MT
        elif isinstance(tx, TransferTransaction):
            legacy_type = qrllegacy_pb2.LegacyMessage.TX
        elif isinstance(tx, TokenTransaction):
            legacy_type = qrllegacy_pb2.LegacyMessage.TK
        elif isinstance(tx, TransferTokenTransaction):
            legacy_type = qrllegacy_pb2.LegacyMessage.TT
        elif isinstance(tx, SlaveTransaction):
            legacy_type = qrllegacy_pb2.LegacyMessage.SL
        elif isinstance(tx, LatticeTransaction):
            legacy_type = qrllegacy_pb2.LegacyMessage.LT
        elif isinstance(tx, MultiSigCreate):
            legacy_type = qrllegacy_pb2.LegacyMessage.MC
        elif isinstance(tx, MultiSigSpend):
            legacy_type = qrllegacy_pb2.LegacyMessage.MS
        elif isinstance(tx, MultiSigVote):
            legacy_type = qrllegacy_pb2.LegacyMessage.MV
        else:
            raise ValueError('Invalid Transaction Type')
        self.register_and_broadcast(legacy_type, tx.get_message_hash(), tx.pbdata)

    def broadcast_block(self, block: Block):
        # logger.info('<<<Transmitting block: ', block.headerhash)
        data = qrllegacy_pb2.MRData()
        data.stake_selector = block.transactions[0].public_key
        data.block_number = block.block_number
        data.prev_headerhash = bytes(block.prev_headerhash)

        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, block.pbdata, data)

    def register_and_broadcast(self, msg_type, msg_hash: bytes, pbdata, data=None):
        self.master_mr.register(msg_type, msg_hash, pbdata)
        self.broadcast(msg_type, msg_hash, data)

    def broadcast(self, msg_type, msg_hash: bytes, mr_data=None):
        """
        Broadcast
        This function sends the Message Receipt to all connected peers.
        :return:
        """
        ignore_peers = []
        if msg_hash in self.master_mr.requested_hash:
            ignore_peers = self.master_mr.requested_hash[msg_hash].peers_connection_list

        if not mr_data:
            mr_data = qrllegacy_pb2.MRData()

        mr_data.hash = msg_hash
        mr_data.type = msg_type
        data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.MR,
                                           mrData=mr_data)

        for peer in self._peer_connections:
            if peer not in ignore_peers:
                peer.send(data)

    def broadcast_get_synced_state(self):
        # Request all peers to update their synced status
        for peer in self._peer_connections:
            peer.send_sync()

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Event handlers / Comms related

    def start_listening(self):
        reactor.listenTCP(config.user.p2p_local_port, self)

    def clientConnectionLost(self, connector, reason):  # noqa
        logger.debug('connection lost: %s', reason)

    def clientConnectionFailed(self, connector, reason):
        logger.debug('connection failed: %s', reason)

    def startedConnecting(self, connector):
        logger.debug('Started connecting: %s', connector)

    def add_connection(self, conn_protocol) -> bool:
        # TODO: Most of this can go peer manager
        if self._qrl_node.peer_manager.is_banned(conn_protocol.peer):
            return False

        redundancy_count = 0
        for conn in self._peer_connections:
            if conn.peer.ip == conn_protocol.peer.ip:
                redundancy_count += 1

        if config.user.max_redundant_connections >= 0:
            if redundancy_count >= config.user.max_redundant_connections:
                logger.info('Redundant Limit. Disconnecting client %s', conn_protocol.peer)
                return False

        if self.reached_conn_limit:
            # FIXME: Should we stop listening to avoid unnecessary load due to many connections?
            logger.info('Peer limit hit. Disconnecting client %s', conn_protocol.peer)
            return False

        # Remove your own ip address from the connection
        if conn_protocol.peer.ip == conn_protocol.host.ip and conn_protocol.peer.port == config.user.p2p_public_port:
            peer_list = [p for p in self._qrl_node.peer_manager.known_peer_addresses if p != conn_protocol.peer.full_address]
            self._qrl_node.peer_manager.extend_known_peers(peer_list)
            return False

        self._peer_connections.append(conn_protocol)

        logger.debug('>>> new connection: %s ', conn_protocol.peer)
        return True

    def remove_connection(self, conn_protocol):
        if conn_protocol in self._peer_connections:
            self._peer_connections.remove(conn_protocol)

        if conn_protocol.peer.full_address in self.peer_blockheight:
            del self.peer_blockheight[conn_protocol.peer.full_address]

    def monitor_connections(self):
        reactor.callLater(config.user.monitor_connections_interval, self.monitor_connections)

        if len(self._peer_connections) == 0:
            logger.warning('No Connected Peer Found')
            known_peers = self._qrl_node.peer_manager.load_known_peers()
            self._peer_q.extend(known_peers)

        connected_peers_set = set()
        for conn_protocol in self._peer_connections:
            connected_peers_set.add(conn_protocol.peer.full_address)

        for peer_item in config.user.peer_list:
            peer_metadata = IPMetadata.from_full_address(peer_item)
            if peer_metadata.full_address in self._peer_q:
                self._peer_q.remove(peer_metadata.full_address)
            if peer_metadata.full_address not in connected_peers_set:
                self.connect_peer([peer_metadata.full_address])

        if len(self._peer_connections) >= config.user.max_peers_limit:
            return

        if len(self._peer_q) == 0:
            return

        peer_address_list = []
        max_length = min(10, config.user.max_peers_limit)
        while len(self._peer_q) > 0 and len(peer_address_list) != max_length:
            peer_address_list.append(self._peer_q.pop(0))

        self.connect_peer(peer_address_list)

    def connect_peer(self, full_address_list):
        for full_address in full_address_list:
            try:
                addr = IPMetadata.from_full_address(full_address)

                connected_peers = self.get_connected_peer_addrs()
                should_connect = addr.full_address not in connected_peers

                if should_connect:
                    reactor.connectTCP(addr.ip, addr.port, self)

            except Exception as e:
                logger.warning("Could not connect to %s - %s", full_address, str(e))
