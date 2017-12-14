# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import time
import queue
import random

from qrl.core.ESyncState import ESyncState
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from qrl.core import config, logger, ntp
from qrl.core.Block import Block
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Transaction import Vote, StakeTransaction, DestakeTransaction, TransferTransaction, LatticePublicKey
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.node import SyncState
from qrl.core.p2pprotocol import P2PProtocol
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrllegacy_pb2


class P2PFactory(ServerFactory):
    protocol = P2PProtocol

    def __init__(self,
                 buffered_chain: BufferedChain,
                 sync_state: SyncState,
                 qrl_node: QRLNode):

        self.master_mr = MessageReceipt()
        self.pos = None
        self.sync_state = sync_state

        self._ntp = ntp
        self._qrl_node = qrl_node
        self._buffered_chain = buffered_chain

        self._genesis_processed = False
        self._peer_connections = []
        self._synced_peers_protocol = set()
        self._txn_processor_running = False

        # Blocknumber for which bkmr is being tracked
        self.bkmr_blocknumber = 0  # FIXME: Accessed by every p2pprotocol instance
        self.bkmr_priorityq = queue.PriorityQueue()  # FIXME: Accessed by every p2pprotocol instance

        # Scheduled and cancel the call, just to initialize with IDelayedCall
        self.bkmr_processor = reactor.callLater(1, lambda: None, pos=None)  # FIXME: Accessed by every p2pprotocol
        self.bkmr_processor.cancel()

        self._last_requested_block_idx = None

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################

    @property
    def connections(self):
        return len(self._peer_connections)

    @property
    def has_synced_peers(self):
        return len(self._synced_peers_protocol) > 0

    @property
    def synced(self):
        return self.pos.sync_state.state == ESyncState.synced

    @property
    def reached_conn_limit(self):
        return len(self._peer_connections) >= config.user.max_peers_limit

    def get_random_synced_peer(self):
        return random.sample(self._synced_peers_protocol, 1)[0]

    def get_connected_peer_ips(self):
        # FIXME: Convert self._peer_connections to set
        return set([peer.peer_ip for peer in self._peer_connections])

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################

    @property
    def chain_height(self):
        return self._buffered_chain.height

    def get_block(self, block_number):
        return self._buffered_chain.get_block(block_number)

    def block_received(self, block: Block):
        self.pos.last_pb_time = time.time()
        logger.info('>>> Received Block #%d', block.block_number)

        if not self._buffered_chain.check_expected_headerhash(block.block_number,
                                                              block.headerhash):
            logger.warning('Block #%s downloaded from peer doesnt match with expected headerhash',
                           block.block_number)
            return

        if block.block_number != self._last_requested_block_idx:
            logger.warning('Did not match %s', self._last_requested_block_idx)
            return

        self._last_requested_block_idx = None

        # FIXME: This check should not be necessary
        if block.block_number > self.chain_height:
            if not self._buffered_chain.add_block(block):
                logger.warning('PB failed to add block to mainchain')
                self._buffered_chain.remove_last_buffer_block()
                return

        try:
            reactor.download_monitor.cancel()
        except Exception as e:
            logger.warning("PB: %s", e)

        self.randomize_block_fetch()  # NOTE: Get next block

    def randomize_block_fetch(self):
        if self.sync_state.state != ESyncState.syncing:
            return

        if self.sync_state.state == ESyncState.syncing:
            block = self._buffered_chain.get_last_block()
            block_timestamp = block.timestamp
            if self.pos.isSynced(block_timestamp):
                return

        if not self.has_synced_peers:
            logger.warning('No connected peers in synced state. Retrying...')
            self.pos.update_node_state(ESyncState.unsynced)
            return

        reactor.download_monitor = reactor.callLater(20, self.randomize_block_fetch)

        random_peer = self.get_random_synced_peer()
        block_index = self._buffered_chain.height + 1

        self._last_requested_block_idx = block_index
        random_peer.send_fetch_block(block_index)

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Encapsulating code that is node related

    def set_peer_synced(self, conn_protocol, synced: bool):
        if synced:
            self._synced_peers_protocol.add(conn_protocol)
        else:
            self._synced_peers_protocol.discard(conn_protocol)

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

    def select_best_bkmr(self):
        # FIXME: This seems to be a much higher level behavior
        blocknumber = self.bkmr_blocknumber
        try:
            dscore, dhash = self.bkmr_priorityq.get_nowait()
            if blocknumber <= self._buffered_chain.height:
                oldscore = self._buffered_chain.get_block_score(blocknumber)
                if dscore > oldscore:
                    del self.bkmr_priorityq
                    self.bkmr_priorityq = queue.PriorityQueue()
                    return

            data = qrllegacy_pb2.MRData()

            data.hash = dhash
            data.type = qrllegacy_pb2.LegacyMessage.BK

            self.request_full_message(data)
            self.bkmr_processor = reactor.callLater(5, self.select_best_bkmr)
        except queue.Empty:
            return
        except Exception as e:
            logger.error('select_best_bkmr Unexpected Exception')
            logger.error('%s', e)

    ##############################################
    ##############################################
    ##############################################
    ##############################################
    # NOTE: PoS related.. broadcasting, etc. OBSOLETE
    def broadcast_st(self, st: StakeTransaction):
        logger.info('<<<Transmitting ST: %s', st.activation_blocknumber)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.ST, st.get_message_hash(), st.pbdata)

    def broadcast_vote(self, vote: Vote):
        logger.info('<<<Transmitting Vote Txn: %s', vote.blocknumber)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.VT, vote.get_message_hash(), vote.pbdata)

    def broadcast_destake(self, destake_txn: DestakeTransaction):
        logger.info('<<<Transmitting Destake Txn: %s', destake_txn.txfrom)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.DST, destake_txn.get_message_hash(),
                                    destake_txn.to_json())

    def broadcast_tx(self, tx: TransferTransaction):
        logger.info('<<<Transmitting TX: %s', tx.txhash)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.TX, tx.get_message_hash(), tx.to_json())

    def broadcast_lt(self, lattice_public_key_txn: LatticePublicKey):
        logger.info('<<<Transmitting LATTICE txn: %s', lattice_public_key_txn.txhash)
        self._buffered_chain.add_lattice_public_key(lattice_public_key_txn)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.LT, lattice_public_key_txn.get_message_hash(),
                                    lattice_public_key_txn.to_json())

    def broadcast_tx_relay(self, source_peer, tx):
        txn_msg = source_peer._wrap_message('TX', tx.to_json())
        for peer in self._peer_connections:
            if peer != source_peer:
                peer.transport.write(txn_msg)

    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def broadcast_block(self, block: Block):
        # logger.info('<<<Transmitting block: ', block.headerhash)
        data = qrllegacy_pb2.MRData()
        data.stake_selector = block.transactions[0].addr_from
        data.block_number = block.block_number
        data.prev_headerhash = bytes(block.prev_headerhash)

        if block.block_number > 1:
            data.reveal_hash = block.reveal_hash

        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, block.pbdata, data)

    ##############################################
    ##############################################
    ##############################################
    ##############################################

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
        self._synced_peers_protocol = set()
        for peer in self._peer_connections:
            peer.send_sync()

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Event handlers
    # NOTE: No need to refactor, it is obsolete
    def clientConnectionLost(self, connector, reason):  # noqa
        logger.debug('connection lost: %s', reason)

    def clientConnectionFailed(self, connector, reason):
        logger.debug('connection failed: %s', reason)

    def startedConnecting(self, connector):
        logger.debug('Started connecting: %s', connector)

    def add_connection(self, conn_protocol) -> bool:
        # TODO: Most of this can go the peer manager

        # FIXME: (For AWS) This could be problematic for other users
        # FIXME: identify nodes by an GUID?
        if config.dev.public_ip and conn_protocol.peer_ip == config.dev.public_ip:
            conn_protocol.loseConnection()
            return False

        if self.reached_conn_limit:
            # FIXME: Should we stop listening to avoid unnecessary load due to many connections?
            logger.info('Peer limit hit. Disconnecting client %s', conn_protocol.peer_ip)
            conn_protocol.loseConnection()
            return False

        peer_list = self._qrl_node.peer_addresses
        if conn_protocol.peer_ip == conn_protocol.host_ip:
            if conn_protocol.peer_ip in peer_list:
                logger.info('Self in peer_list, removing..')
                peer_list.remove(conn_protocol.peer_ip)
                self._qrl_node.peer_manager.update_peer_addresses(peer_list)

            conn_protocol.loseConnection()
            return False

        self._peer_connections.append(conn_protocol)

        if conn_protocol.peer_ip not in peer_list:
            logger.info('Adding to peer_list')
            peer_list.add(conn_protocol.peer_ip)
            self._qrl_node.peer_manager.update_peer_addresses(peer_list)

        logger.info('>>> new peer connection : %s:%s ', conn_protocol.peer_ip, str(conn_protocol.peer_port))

        # FIXME: This seem PoS related
        if self._buffered_chain.height == 0 and not self._genesis_processed:
            # set the flag so that no other Protocol instances trigger the genesis stake functions..
            self._genesis_processed = True
            logger.info('genesis pos countdown to block 1 begun, 60s until stake tx circulated..')
            reactor.callLater(1, self.pos.pre_pos_1)

        return True

    def remove_connection(self, conn_protocol):
        if conn_protocol in self._peer_connections:
            self._peer_connections.remove(conn_protocol)

        self._synced_peers_protocol.discard(conn_protocol)

        if self.connections == 0:
            reactor.callLater(60, self.connect_peers)

    def connect_peer(self, peer_address):
        if peer_address not in self.get_connected_peer_ips():
            reactor.connectTCP(peer_address, 9000, self)

    def connect_peers(self):
        """
        Will connect to all known peers. This is typically the entry point
        It does result in:
        - connectionMade in each protocol (session)
        - :py:meth:startedConnecting
        - :py:meth:clientConnectionFailed
        - :py:meth:clientConnectionLost
        :return:
        :rtype: None
        """
        # FIXME: This probably should be in the qrl_node
        logger.info('<<<Reconnecting to peer list: %s', self._qrl_node.peer_addresses)
        for peer_address in self._qrl_node.peer_addresses:
            self.connect_peer(peer_address)
