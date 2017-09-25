# coding=utf-8
import pickle as pickle
import os
import random
import struct
import time
from collections import defaultdict

import simplejson as json
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from pyqrllib.pyqrllib import bin2hstr
from qrl.core import config, logger, helper
from qrl.core.helper import json_encode, json_bytestream, json_bytestream_bk
from qrl.core.p2pprotocol import P2PProtocol
from qrl.crypto.misc import sha256
import queue


class P2PFactory(ServerFactory):
    protocol = P2PProtocol

    def __init__(self, chain, nodeState, pos=None):
        # FIXME: Constructor signature is not consistent with other factory classes
        self.master_mr = None
        self.pos = None
        self.chain = chain
        self.nodeState = nodeState
        self.stake = config.user.enable_auto_staking  # default to mining off as the wallet functions are not that responsive at present with it enabled..
        self.peers_blockheight = {}
        self.target_retry = defaultdict(int)
        self.target_peers = {}
        self.fork_target_peers = {}
        self.connections = 0
        self.buffer = ''
        self.sync = 0
        self.partial_sync = [0, 0]
        self.long_gap_block = 0
        self.mining = 0
        self.newblock = 0
        self.exit = 0
        self.genesis = 0
        self.missed_block = 0
        self.requested = [0, 0]
        self.ip_geotag = 1  # to be disabled in main release as reveals IP..
        self.last_reveal_one = None
        self.last_reveal_two = None
        self.last_reveal_three = None

        self.peer_connections = []
        self.peer_addresses = []
        self.peers_path = os.path.join(config.user.data_path, config.dev.peers_filename)
        self.load_peer_addresses()
        self.txn_processor_running = False

        self.bkmr_blocknumber = 0  # Blocknumber for which bkmr is being tracked
        self.bkmr_priorityq = queue.PriorityQueue()
        # Scheduled and cancel the call, just to initialize with IDelayedCall
        self.bkmr_processor = reactor.callLater(1, self.setPOS, pos=None)
        self.bkmr_processor.cancel()

    # factory network functions
    def setPOS(self, pos):
        self.pos = pos
        self.master_mr = self.pos.master_mr

    def RFM(self, data):
        """
        Request Full Message
        This function request for the full message against,
        the Message Receipt received.
        :return:
        """

        # FIXME: Again, breaking encasulation
        # FIXME: Huge amount of lookups in dictionaries

        msg_hash = data['hash']
        msg_hash_str = bin2hstr(msg_hash)

        if msg_hash_str in self.master_mr.hash_msg:
            if msg_hash_str in self.master_mr.hash_callLater:
                del self.master_mr.hash_callLater[msg_hash_str]
            return
        for peer in self.master_mr.hash_peer[msg_hash_str]:
            if peer not in self.master_mr.requested_hash[msg_hash_str]:
                self.master_mr.requested_hash[msg_hash_str].append(peer)
                # Storing MR params, so the received full message could be checked against
                # the MR receipt provided.
                self.master_mr.hash_params[msg_hash_str] = data
                peer.transport.write(peer.wrap_message('SFM', helper.json_encode(data)))
                call_later_obj = reactor.callLater(config.dev.message_receipt_timeout,
                                                   self.RFM,
                                                   data)
                self.master_mr.hash_callLater[msg_hash_str] = call_later_obj
                return

        # If executing reach to this line, then it means no peer was able to provide
        # Full message for this hash thus the hash has to be deleted.
        # Moreover, negative points could be added to the peers, for this behavior
        if msg_hash_str in self.master_mr.hash_callLater:
            del self.master_mr.hash_callLater[msg_hash_str]

    def select_best_bkmr(self):
        block_chain_buffer = self.chain.block_chain_buffer
        blocknumber = self.bkmr_blocknumber
        try:
            score, hash = self.bkmr_priorityq.get_nowait()
            if blocknumber <= block_chain_buffer.height():
                oldscore = block_chain_buffer.get_block_n_score(blocknumber)
                if score > oldscore:
                    del self.bkmr_priorityq
                    self.bkmr_priorityq = queue.PriorityQueue()

            self.RFM(data={'hash': hash, 'type': 'BK'})
            self.bkmr_processor = reactor.callLater(5, self.select_best_bkmr)
        except queue.Empty:
            return
        except Exception as e:
            logger.error('select_best_bkmr Unexpected Exception')
            logger.error('%s', e)

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
        logger.info('<<<Reconnecting to peer list: %s', self.peer_addresses)
        for peer in self.peer_addresses:
            reactor.connectTCP(peer, 9000, self)

    def get_block_a_to_b(self, a, b):
        logger.info('<<<Requested blocks: %s to %s from peers..', a, b)
        l = list(range(a, b))
        for peer in self.peer_connections:
            if len(l) > 0:
                peer.transport.write(self.protocol.wrap_message('BN', str(l.pop(0))))
            else:
                return

    def get_block_n_random_peer(self, n):
        logger.info('<<<Requested block: %s from random peer.', n)
        random.choice(self.peer_connections).get_block_n(n)
        return

    def get_block_n(self, n):
        logger.info('<<<Requested block: %s from peers.', n)
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('BN', str(n)))
        return

    def get_m_blockheight_from_random_peer(self):
        logger.info('<<<Requested blockheight from random peer.')
        random.choice(self.peer_connections).get_m_blockheight_from_connection()
        return

    def get_blockheight_map_from_peers(self):
        logger.info('<<<Requested blockheight_map from peers.')
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('BM'))
        return

    def get_m_blockheight_from_peers(self):
        for peer in self.peer_connections:
            peer.get_m_blockheight_from_connection()
        return

    def send_m_blockheight_to_peers(self):
        logger.info('<<<Sending blockheight to peers.')
        for peer in self.peer_connections:
            peer.send_m_blockheight_to_peer()
        return

    def send_st_to_peers(self, st):
        logger.info('<<<Transmitting ST: %s', st.epoch)
        self.register_and_broadcast('ST', st.get_message_hash(), st.transaction_to_json())
        return

    def send_tx_to_peers(self, tx):
        logger.info('<<<Transmitting TX: %s', bin2hstr(tx.txhash))
        self.register_and_broadcast('TX', tx.get_message_hash(), tx.transaction_to_json())
        return

    def send_reboot(self, json_hash):
        logger.info('<<<Transmitting Reboot Command')
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('reboot', json_hash))
        return

    # transmit reveal_one hash.. (node cast lottery vote)

    def send_stake_reveal_one(self, blocknumber=None):
        if blocknumber is None:
            blocknumber = self.chain.block_chain_buffer.height() + 1  # next block..

        reveal_msg = {'stake_address': self.chain.mining_address,
                      'block_number': blocknumber,
                      # demonstrate the hash from last block to prevent building upon invalid block..
                      'headerhash': self.chain.block_chain_buffer.get_strongest_headerhash(blocknumber - 1)}

        epoch = blocknumber // config.dev.blocks_per_epoch

        hash_chain = self.chain.block_chain_buffer.hash_chain_get(blocknumber)
        # +1 to skip first reveal
        reveal_msg['reveal_one'] = hash_chain[-1][:-1][::-1][blocknumber - (epoch * config.dev.blocks_per_epoch) + 1]
        reveal_msg['vote_hash'] = None
        reveal_msg['weighted_hash'] = None
        epoch_seed = self.chain.block_chain_buffer.get_epoch_seed(blocknumber)
        reveal_msg['seed'] = epoch_seed
        reveal_msg['SV_hash'] = self.chain.get_stake_validators_hash()

        stake_validators_list = self.chain.block_chain_buffer.get_stake_validators_list(blocknumber)
        target_chain = stake_validators_list.select_target(reveal_msg['headerhash'])

        hashes = hash_chain[target_chain]
        reveal_msg['vote_hash'] = hashes[:-1][::-1][blocknumber - (epoch * config.dev.blocks_per_epoch)]

        if reveal_msg['reveal_one'] is None or reveal_msg['vote_hash'] is None:
            logger.info('reveal_one or vote_hash None for stake_address: %s selected hash: %s',
                        reveal_msg['stake_address'],
                        hash_chain[target_chain])
            logger.info('reveal_one %s', reveal_msg['reveal_one'])
            logger.info('vote_hash %s', reveal_msg['vote_hash'])
            logger.info('hash %s', hash_chain[target_chain])
            return

        reveal_msg['weighted_hash'] = self.chain.score(
            stake_address=reveal_msg['stake_address'],
            reveal_one=reveal_msg['reveal_one'],
            balance=self.chain.block_chain_buffer.get_st_balance(reveal_msg['stake_address'], blocknumber),
            seed=epoch_seed)

        y = False
        tmp_stake_reveal_one = []
        for r in self.chain.stake_reveal_one:  # need to check the reveal list for existence already, if so..reuse..
            if r[0] == self.chain.mining_address:
                if r[1] == reveal_msg['headerhash']:
                    if r[2] == blocknumber:
                        if y:
                            continue  # if repetition then remove..
                        else:
                            reveal_msg['reveal_one'] = r[3]
                            y = True
            tmp_stake_reveal_one.append(r)

        self.chain.stake_reveal_one = tmp_stake_reveal_one
        logger.info('<<<Transmitting POS reveal_one %s %s', blocknumber,
                    self.chain.block_chain_buffer.get_st_balance(reveal_msg['stake_address'], blocknumber))

        self.last_reveal_one = reveal_msg
        self.register_and_broadcast('R1', reveal_msg['vote_hash'], json_encode(reveal_msg))

        if not y:
            self.chain.stake_reveal_one.append([reveal_msg['stake_address'],
                                                reveal_msg['headerhash'],
                                                reveal_msg['block_number'],
                                                reveal_msg['reveal_one'],
                                                reveal_msg['weighted_hash'],
                                                reveal_msg['vote_hash']])

        return reveal_msg['reveal_one']

    def send_last_stake_reveal_one(self):
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('R1', json_encode(self.last_reveal_one)))

    def ip_geotag_peers(self):
        logger.info('<<<IP geotag broadcast')
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('IP'))
        return

    def ping_peers(self):
        logger.info('<<<Transmitting network PING')
        self.chain.last_ping = time.time()
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('PING'))
        return

    # send POS block to peers..

    def send_stake_block(self, block_obj):
        logger.info('<<<Transmitting POS created block %s %s', str(block_obj.blockheader.blocknumber),
                    block_obj.blockheader.headerhash)
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('S4', json_bytestream(block_obj)))
        return

    # send/relay block to peers

    def send_block_to_peers(self, block):
        # logger.info('<<<Transmitting block: ', block.blockheader.headerhash)
        extra_data = {'stake_selector': block.transactions[0].txto,
                      'blocknumber': block.blockheader.blocknumber,
                      'prev_headerhash': block.blockheader.prev_blockheaderhash}

        if block.blockheader.blocknumber > 1:
            extra_data['reveal_hash'] = block.blockheader.reveal_hash
            extra_data['vote_hash'] = block.blockheader.vote_hash

        self.register_and_broadcast('BK',
                                    block.blockheader.headerhash,
                                    json_bytestream_bk(block),
                                    extra_data)
        return

    def register_and_broadcast(self, msg_type, msg_hash, msg_json, extra_data=None):
        # FIXME: Try to keep parameters in the same order (consistency)
        self.master_mr.register(msg_hash, msg_json, msg_type)

        msg_hash = sha256(msg_hash)
        data = {'hash': msg_hash,
                'type': msg_type}

        if extra_data:
            for key in extra_data:
                data[key] = extra_data[key]

        for peer in self.peer_connections:
            if msg_hash in self.master_mr.hash_peer:
                if peer in self.master_mr.hash_peer[msg_hash]:
                    continue
            peer.transport.write(self.protocol.wrap_message('MR', json_encode(data)))

    # request transaction_pool from peers

    def get_tx_pool_from_peers(self):
        logger.info('<<<Requesting TX pool from peers..')
        for peer in self.peer_connections:
            peer.transport.write(self.protocol.wrap_message('RT'))
        return

    # connection functions

    # FIXME: Temporarily moving here
    def load_peer_addresses(self):
        if os.path.isfile(self.peers_path) is True:
            logger.info('Opening peers.dat')
            with open(self.peers_path, 'rb') as my_file:
                self.peer_addresses = pickle.load(my_file)
        else:
            logger.info('Creating peers.dat')
            # Ensure the data path exists
            config.create_path(config.user.data_path)
            with open(self.peers_path, 'wb') as my_file:
                pickle.dump(config.user.peer_list, my_file)
                self.peer_addresses = config.user.peer_list

        logger.info('Known Peers: %s', self.peer_addresses)

    def update_peer_addresses(self, peer_addresses):
        self.peer_addresses = peer_addresses
        with open(self.peers_path, "wb") as myfile:
            pickle.dump(self.peer_addresses, myfile)

    def reset_processor_flag(self, _):
        self.txn_processor_running = False

    def reset_processor_flag_with_err(self, msg):
        logger.error('Exception in txn task')
        logger.error('%s', msg)
        self.txn_processor_running = False

    # Event handlers
    def clientConnectionLost(self, connector, reason):
        logger.debug('connection lost: %s', reason)
        # TODO: Reconnect has been disabled
        # connector.connect()

    def clientConnectionFailed(self, connector, reason):
        logger.debug('connection failed: %s', reason)

    def startedConnecting(self, connector):
        logger.debug('Started connecting: %s', connector)
