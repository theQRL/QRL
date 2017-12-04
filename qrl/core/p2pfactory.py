# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import queue
import random

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from qrl.core import config, logger, ntp
from qrl.core.Block import Block
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Transaction import Vote, StakeTransaction, DestakeTransaction
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.node import SyncState
from qrl.core.p2pprotocol import P2PProtocol
from qrl.core.processors.TxnProcessor import TxnProcessor
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrllegacy_pb2


class P2PFactory(ServerFactory):
    protocol = P2PProtocol

    def __init__(self,
                 buffered_chain: BufferedChain,
                 sync_state: SyncState,
                 qrl_node: QRLNode):
        self.services_arg = {
            ######################
            qrllegacy_pb2.LegacyMessage.VE: 'veData',
            qrllegacy_pb2.LegacyMessage.PL: 'plData',
            qrllegacy_pb2.LegacyMessage.PONG: 'pongData',

            ######################
            qrllegacy_pb2.LegacyMessage.MR: 'mrData',
            qrllegacy_pb2.LegacyMessage.SFM: 'sfmData',

            qrllegacy_pb2.LegacyMessage.BK: 'bkData',
            qrllegacy_pb2.LegacyMessage.FB: 'fbData',
            qrllegacy_pb2.LegacyMessage.PB: 'pbData',

            ############################
            qrllegacy_pb2.LegacyMessage.ST: 'stData',
            qrllegacy_pb2.LegacyMessage.DST: '',
            qrllegacy_pb2.LegacyMessage.DT: '',

            ############################
            qrllegacy_pb2.LegacyMessage.TX: '',
            qrllegacy_pb2.LegacyMessage.VT: 'vtData',
            qrllegacy_pb2.LegacyMessage.LT: '',

            qrllegacy_pb2.LegacyMessage.EPH: '',

            qrllegacy_pb2.LegacyMessage.SYNC: 'syncData',
        }
        self.master_mr = MessageReceipt()
        self.pos = None
        self.ntp = ntp
        self.qrl_node = qrl_node
        self.buffered_chain = buffered_chain
        self.sync_state = sync_state

        self._genesis_processed = False
        self._peer_connections = []
        self._synced_peers_protocol = set()

        self._txn_processor_running = False  # FIXME: Accessed by every p2pprotocol instance

        # Blocknumber for which bkmr is being tracked
        self.bkmr_blocknumber = 0                    # FIXME: Accessed by every p2pprotocol instance
        self.bkmr_priorityq = queue.PriorityQueue()  # FIXME: Accessed by every p2pprotocol instance

        # Scheduled and cancel the call, just to initialize with IDelayedCall
        self.bkmr_processor = reactor.callLater(1, lambda: None, pos=None)  # FIXME: Accessed by every p2pprotocol
        self.bkmr_processor.cancel()

    @property
    def connections(self):
        return len(self._peer_connections)

    @property
    def has_synced_peers(self):
        return len(self._synced_peers_protocol) > 0

    @property
    def reached_conn_limit(self):
        return len(self._peer_connections) >= config.user.max_peers_limit

    def get_random_synced_peer(self):
        return random.sample(self._synced_peers_protocol, 1)[0]

    def get_connected_peer_ips(self):
        return set([peer.host_ip for peer in self._peer_connections])

    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def RFM(self, mr_data: qrllegacy_pb2.MRData):
        """
        Request Full Message
        This function request for the full message against,
        the Message Receipt received.
        :return:
        """

        # FIXME: Again, breaking encasulation
        # FIXME: Huge amount of lookups in dictionaries
        msg_hash = mr_data.hash

        if msg_hash in self.master_mr.hash_msg:
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

            data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SFM,
                                               sfmData=qrllegacy_pb2.MRData(hash=mr_data.hash, type=mr_data.type))

            peer.transport.write(peer.wrap_message(data))
            call_later_obj = reactor.callLater(config.dev.message_receipt_timeout,
                                               self.RFM,
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
            if blocknumber <= self.buffered_chain.height:
                oldscore = self.buffered_chain.get_block_score(blocknumber)
                if dscore > oldscore:
                    del self.bkmr_priorityq
                    self.bkmr_priorityq = queue.PriorityQueue()
                    return

            data = qrllegacy_pb2.MRData()

            data.hash = dhash
            data.type = 'BK'

            self.RFM(data)
            self.bkmr_processor = reactor.callLater(5, self.select_best_bkmr)
        except queue.Empty:
            return
        except Exception as e:
            logger.error('select_best_bkmr Unexpected Exception')
            logger.error('%s', e)

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
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.DST, destake_txn.get_message_hash(), destake_txn.to_json())

    def broadcast_block(self, block: Block):
        # logger.info('<<<Transmitting block: ', block.headerhash)
        data = qrllegacy_pb2.MRData()
        data.stake_selector = block.transactions[0].addr_from
        data.block_number = block.block_number
        data.prev_headerhash = bytes(block.prev_headerhash)

        if block.block_number > 1:
            data.reveal_hash = block.reveal_hash

        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, block.to_json(), data)

    def broadcast_tx(self, tx):
        logger.info('<<<Transmitting TX: %s', tx.txhash)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.TX, tx.get_message_hash(), tx.to_json())

    def broadcast_lt(self, lattice_public_key_txn):
        logger.info('<<<Transmitting LATTICE txn: %s', lattice_public_key_txn.txhash)
        self.buffered_chain.add_lattice_public_key(lattice_public_key_txn)
        self.register_and_broadcast(qrllegacy_pb2.LegacyMessage.LT, lattice_public_key_txn.get_message_hash(), lattice_public_key_txn.to_json())

    def register_and_broadcast(self, msg_type, msg_hash: bytes, pbdata, data=None):
        self.master_mr.register(msg_type, msg_hash, pbdata)
        self.broadcast(msg_type, msg_hash, data)

    def broadcast_relay(self, source_peer, raw_message):
        for peer in self._peer_connections:
            if peer != source_peer:
                peer.transport.write(raw_message)

    def broadcast(self, msg_type, msg_hash: bytes, data=None):  # Move to factory
        """
        Broadcast
        This function sends the Message Receipt to all connected peers.
        :return:
        """
        ignore_peers = []
        if msg_hash in self.master_mr.requested_hash:
            ignore_peers = self.master_mr.requested_hash[msg_hash].peers_connection_list

        if not data:
            data = qrllegacy_pb2.MRData()

        data.hash = msg_hash
        data.type = msg_type
        data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.MR,
                                           mrData=qrllegacy_pb2.MRData(hash=msg_hash, type=msg_type))

        msg = self.protocol.wrap_message(data)
        for peer in self._peer_connections:
            if peer not in ignore_peers:
                peer.transport.write(msg)

    def broadcast_get_synced_state(self):
        # Request all peers to update their synced status
        self._synced_peers_protocol = set()
        for peer in self._peer_connections:
            peer.send_sync()

    ###################################################
    ###################################################
    ###################################################
    # NOTE: tx processor related. Obsolete stage 2?

    def reset_processor_flag(self, _):
        self._txn_processor_running = False

    def reset_processor_flag_with_err(self, msg):
        logger.error('Exception in txn task')
        logger.error('%s', msg)
        self._txn_processor_running = False

    def trigger_tx_processor(self, tx, json_tx_obj):
        # duplicate tx already received, would mess up nonce..
        for t in self.factory.buffered_chain.tx_pool.transaction_pool:
            if tx.txhash == t.txhash:
                return

        self.buffered_chain.tx_pool.update_pending_tx_pool(tx, self)
        self.master_mr.register(qrllegacy_pb2.LegacyMessage.TX, tx.get_message_hash(), json_tx_obj)
        self.broadcast(qrllegacy_pb2.LegacyMessage.TX, tx.get_message_hash())

        if not self._txn_processor_running:
            # FIXME: TxnProcessor breaks tx_pool encapsulation
            txn_processor = TxnProcessor(buffered_chain=self.buffered_chain,
                                         pending_tx_pool=self.buffered_chain.tx_pool.pending_tx_pool,
                                         transaction_pool=self.buffered_chain.tx_pool.transaction_pool)

            task_defer = TxnProcessor.create_cooperate(txn_processor).whenDone()

            task_defer\
                .addCallback(self.reset_processor_flag)\
                .addErrback(self.reset_processor_flag_with_err)

            self._txn_processor_running = True

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

    def set_peer_synced(self, conn_protocol, synced: bool):
        if synced:
            self._synced_peers_protocol.add(conn_protocol)
        else:
            self._synced_peers_protocol.discard(conn_protocol)

    def add_connection(self, conn_protocol) -> bool:
        # FIXME: (For AWS) This could be problematic for other users
        # FIXME: identify nodes by an GUID?
        if config.dev.public_ip and conn_protocol.transport.getPeer().host == config.dev.public_ip:
            conn_protocol.transport.loseConnection()
            return False

        if self.reached_conn_limit:
            # FIXME: Should we stop listening to avoid unnecessary load due to many connections?
            logger.info('Peer limit hit. Disconnecting client %s', conn_protocol.transport.getPeer().host)
            conn_protocol.transport.loseConnection()
            return False

        peer_list = self.qrl_node.peer_addresses
        if conn_protocol.transport.getPeer().host == conn_protocol.transport.getHost().host:
            if conn_protocol.transport.getPeer().host in peer_list:
                logger.info('Self in peer_list, removing..')
                peer_list.remove(conn_protocol.transport.getPeer().host)
                self.qrl_node.update_peer_addresses(peer_list)

            conn_protocol.transport.loseConnection()
            return False

        self._peer_connections.append(conn_protocol)

        if conn_protocol.transport.getPeer().host not in peer_list:
            logger.info('Adding to peer_list')
            peer_list.add(conn_protocol.transport.getPeer().host)
            self.qrl_node.update_peer_addresses(peer_list)

        logger.info('>>> new peer connection : %s:%s ', conn_protocol.transport.getPeer().host,
                    str(conn_protocol.transport.getPeer().port))

        # FIXME: This seem PoS related
        if self.buffered_chain.height == 0 and not self._genesis_processed:
            # set the flag so that no other Protocol instances trigger the genesis stake functions..
            self._genesis_processed = True
            logger.info('genesis pos countdown to block 1 begun, 60s until stake tx circulated..')
            reactor.callLater(1, self.pos.pre_pos_1)

    def remove_connection(self, conn_protocol):
        if conn_protocol in self._peer_connections:
            self._peer_connections.remove(conn_protocol)

        self._synced_peers_protocol.discard(conn_protocol)

        if self.connections == 0:
            reactor.callLater(60, self.connect_peers)

    def connect_peer(self, peer_address):
        # FIXME: this should be kept as a set
        connected_peers = set([peer_conn.transport.getPeer().host for peer_conn in self._peer_connections])

        if peer_address not in connected_peers:
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
        logger.info('<<<Reconnecting to peer list: %s', self.qrl_node._peer_addresses)
        for peer_address in self.qrl_node._peer_addresses:
            self.connect_peer(peer_address)
