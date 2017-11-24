# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import queue

from google.protobuf.json_format import MessageToJson
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from qrl.core import config, logger, ntp
from qrl.core.Block import Block
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Transaction import Vote, StakeTransaction, DestakeTransaction
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.node import SyncState
from qrl.core.p2pprotocol import P2PProtocol
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2


class P2PFactory(ServerFactory):
    protocol = P2PProtocol

    def __init__(self,
                 buffered_chain: BufferedChain,
                 sync_state: SyncState,
                 qrl_node: QRLNode):

        # FIXME: Constructor signature is not consistent with other factory classes
        self.master_mr = MessageReceipt()
        self.pos = None
        self.ntp = ntp
        self.buffered_chain = buffered_chain
        self.sync_state = sync_state

        self.sync = 0

        self.genesis_processed = False      # FIXME: Accessed by every p2pprotocol instance
        self.peer_connections = []          # FIXME: Accessed by every p2pprotocol instance
        self.synced_peers = set()           # FIXME: Accessed by every p2pprotocol instance

        self.qrl_node = qrl_node

        self.txn_processor_running = False

        self.bkmr_blocknumber = 0  # Blocknumber for which bkmr is being tracked
        self.bkmr_priorityq = queue.PriorityQueue()
        # Scheduled and cancel the call, just to initialize with IDelayedCall
        self.bkmr_processor = reactor.callLater(1, lambda: None, pos=None)
        self.bkmr_processor.cancel()

    @property
    def connections(self):
        return len(self.peer_connections)

    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def RFM(self, data):
        """
        Request Full Message
        This function request for the full message against,
        the Message Receipt received.
        :return:
        """

        # FIXME: Again, breaking encasulation
        # FIXME: Huge amount of lookups in dictionaries

        msg_hash = data.hash

        if msg_hash in self.master_mr.hash_msg:
            if msg_hash in self.master_mr.requested_hash:
                del self.master_mr.requested_hash[msg_hash]
            return

        peers_list = self.master_mr.requested_hash[msg_hash].peers_connection_list
        message_request = self.master_mr.requested_hash[msg_hash]
        for peer in peers_list:
            if peer in message_request.already_requested_peers:
                continue
            message_request.already_requested_peers.append(peer)

            peer.transport.write(peer.wrap_message('SFM', MessageToJson(data)))
            call_later_obj = reactor.callLater(config.dev.message_receipt_timeout,
                                               self.RFM,
                                               data)
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

            data = qrl_pb2.MR()

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
        self.register_and_broadcast('ST', st.get_message_hash(), st.to_json())

    def broadcast_vote(self, vote: Vote):
        logger.info('<<<Transmitting Vote Txn: %s', vote.blocknumber)
        self.register_and_broadcast('VT', vote.get_message_hash(), vote.to_json())

    def broadcast_destake(self, destake_txn: DestakeTransaction):
        logger.info('<<<Transmitting Destake Txn: %s', destake_txn.txfrom)
        self.register_and_broadcast('DST', destake_txn.get_message_hash(), destake_txn.to_json())

    def broadcast_block(self, block: Block):
        # logger.info('<<<Transmitting block: ', block.headerhash)
        data = qrl_pb2.MR()
        data.stake_selector = block.transactions[0].addr_from
        data.block_number = block.block_number
        data.prev_headerhash = bytes(block.prev_headerhash)

        if block.block_number > 1:
            data.reveal_hash = block.reveal_hash

        self.register_and_broadcast('BK', block.headerhash, block.to_json(), data)

    def broadcast_tx(self, tx):
        logger.info('<<<Transmitting TX: %s', tx.txhash)
        self.register_and_broadcast('TX', tx.get_message_hash(), tx.to_json())

    def broadcast_lt(self, lattice_public_key_txn):
        logger.info('<<<Transmitting LATTICE txn: %s', lattice_public_key_txn.txhash)
        self.buffered_chain.add_lattice_public_key(lattice_public_key_txn)
        self.register_and_broadcast('LT', lattice_public_key_txn.get_message_hash(), lattice_public_key_txn.to_json())

    def register_and_broadcast(self, msg_type, msg_hash: bytes, msg_json: str, data=None):
        self.master_mr.register(msg_type, msg_hash, msg_json)
        self.broadcast(msg_hash, msg_type, data)

    def broadcast(self, msg_hash: bytes, msg_type, data=None):  # Move to factory
        """
        Broadcast
        This function sends the Message Receipt to all connected peers.
        :return:
        """
        ignore_peers = []
        if msg_hash in self.master_mr.requested_hash:
            ignore_peers = self.master_mr.requested_hash[msg_hash].peers_connection_list

        if not data:
            data = qrl_pb2.MR()

        data.hash = msg_hash
        data.type = msg_type

        for peer in self.peer_connections:
            if peer not in ignore_peers:
                peer.transport.write(self.protocol.wrap_message('MR', MessageToJson(data)))

    def broadcast_get_synced_state(self):
        # Request all peers to update their synced status
        self.synced_peers = set()
        for peer in self.peer_connections:
            peer.transport.write(peer.wrap_message('SYNC'))

    ###################################################
    ###################################################
    ###################################################
    # NOTE: tx processor related. Obsolete stage 2?

    def reset_processor_flag(self, _):
        self.txn_processor_running = False

    def reset_processor_flag_with_err(self, msg):
        logger.error('Exception in txn task')
        logger.error('%s', msg)
        self.txn_processor_running = False

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Event handlers
    # NOTE: No need to refactor, it is obsolete

    # noinspection PyMethodMayBeStatic
    def clientConnectionLost(self, connector, reason):
        logger.debug('connection lost: %s', reason)
        # TODO: Reconnect has been disabled
        # connector.connect()

    # noinspection PyMethodMayBeStatic
    def clientConnectionFailed(self, connector, reason):
        logger.debug('connection failed: %s', reason)

    # noinspection PyMethodMayBeStatic
    def startedConnecting(self, connector):
        logger.debug('Started connecting: %s', connector)

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
        logger.info('<<<Reconnecting to peer list: %s', self.qrl_node._peer_addresses)
        for peer_address in self.qrl_node._peer_addresses:
            # FIXME: Refactor search
            found = False
            for peer_conn in self.peer_connections:
                if peer_address == peer_conn.transport.getPeer().host:
                    found = True
                    break
            if found:
                continue
            reactor.connectTCP(peer_address, 9000, self)
