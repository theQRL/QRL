import cPickle as pickle
import os
import random
import struct
import time
from collections import defaultdict

import simplejson as json
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

import qrl.core.configuration as config
from qrl.core import helper, logger
from qrl.core.merkle import sha256
from qrl.core.p2pprotocol import P2PProtocol


class P2PFactory(ServerFactory):
    def __init__(self, chain, nodeState, pos=None):
        self.master_mr = None
        self.pos = None
        self.protocol = P2PProtocol
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

    # factory network functions
    def setPOS(self, pos):
        self.pos = pos
        self.master_mr = self.pos.master_mr

    def get_block_a_to_b(self, a, b):
        logger.info('<<<Requested blocks: %s to %s from peers..', a, b)
        l = range(a, b)
        for peer in self.peer_connections:
            if len(l) > 0:
                peer.transport.write(self.f_wrap_message('BN', str(l.pop(0))))
            else:
                return

    def get_block_n_random_peer(self, n):
        logger.info('<<<Requested block: %s from random peer.', n)
        random.choice(self.peer_connections).get_block_n(n)
        return

    def get_block_n(self, n):
        logger.info('<<<Requested block: %s from peers.', n)
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('BN', str(n)))
        return

    def get_m_blockheight_from_random_peer(self):
        logger.info('<<<Requested blockheight from random peer.')
        random.choice(self.peer_connections).get_m_blockheight_from_connection()
        return

    def get_blockheight_map_from_peers(self):
        logger.info('<<<Requested blockheight_map from peers.')
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('BM'))
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

    def f_wrap_message(self, mtype, data=None):
        jdata = {'type': mtype }
        if data:
            jdata['data'] = data
        str_data = json.dumps(jdata)
        return chr(255) + chr(0) + chr(0) + struct.pack('>L', len(str_data)) + chr(0) + str_data + chr(0) + chr(
            0) + chr(255)

    def send_st_to_peers(self, st):
        logger.info('<<<Transmitting ST: %s', st.epoch)
        self.register_and_broadcast('ST', st.get_message_hash(), st.transaction_to_json())
        return

    def send_tx_to_peers(self, tx):
        logger.info('<<<Transmitting TX: %s', tx.txhash)
        self.register_and_broadcast('TX', tx.get_message_hash(), tx.transaction_to_json())
        return

    def send_reboot(self, json_hash):
        logger.info('<<<Transmitting Reboot Command')
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('reboot', json_hash))
        return

    # transmit reveal_one hash.. (node cast lottery vote)

    def send_stake_reveal_one(self, blocknumber=None):

        z = {'stake_address': self.chain.mining_address,
             'block_number': blocknumber}

        if not z['block_number']:
            z['block_number'] = self.chain.block_chain_buffer.height() + 1  # next block..

        z['headerhash'] = self.chain.block_chain_buffer.get_strongest_headerhash(
            z['block_number'] - 1)  # demonstrate the hash from last block to prevent building upon invalid block..
        epoch = z['block_number'] // config.dev.blocks_per_epoch
        hash_chain = self.chain.block_chain_buffer.hash_chain_get(z['block_number'])
        # +1 to skip first reveal
        z['reveal_one'] = hash_chain[-1][:-1][::-1][z['block_number'] - (epoch * config.dev.blocks_per_epoch) + 1]
        z['vote_hash'] = None
        z['weighted_hash'] = None
        epoch_seed = self.chain.block_chain_buffer.get_epoch_seed(blocknumber)
        z['seed'] = epoch_seed
        z['SV_hash'] = self.chain.get_stake_validators_hash()

        _, mhash = self.chain.select_hashchain(
            last_block_headerhash=self.chain.block_chain_buffer.get_strongest_headerhash(z['block_number'] - 1),
            stake_address=self.chain.mining_address, blocknumber=z['block_number'])

        for hashes in hash_chain:
            if hashes[-1] == mhash:
                z['vote_hash'] = hashes[:-1][::-1][z['block_number'] - (epoch * config.dev.blocks_per_epoch)]
                break

        if z['reveal_one'] is None or z['vote_hash'] is None:
            logger.info(
                ('reveal_one or vote_hash None for stake_address: ', z['stake_address'], ' selected hash:', mhash))
            logger.info('reveal_one %s', z['reveal_one'])
            logger.info('vote_hash %s', z['vote_hash'])
            logger.info('hash %s', mhash)
            return

        z['weighted_hash'] = self.chain.score(stake_address=z['stake_address'],
                                              reveal_one=z['reveal_one'],
                                              balance=self.chain.block_chain_buffer.get_st_balance(z['stake_address'],
                                                                                                   blocknumber),
                                              seed=epoch_seed)

        y = False
        tmp_stake_reveal_one = []
        for r in self.chain.stake_reveal_one:  # need to check the reveal list for existence already, if so..reuse..
            if r[0] == self.chain.mining_address:
                if r[1] == z['headerhash']:
                    if r[2] == z['block_number']:
                        if y:
                            continue  # if repetition then remove..
                        else:
                            z['reveal_one'] = r[3]
                            y = True
            tmp_stake_reveal_one.append(r)

        self.chain.stake_reveal_one = tmp_stake_reveal_one
        logger.info('<<<Transmitting POS reveal_one %s %s', blocknumber,
                    self.chain.block_chain_buffer.get_st_balance(z['stake_address'], blocknumber))

        self.last_reveal_one = z
        self.register_and_broadcast('R1', z['vote_hash'], helper.json_encode(z))
        # for peer in self.peers:
        #    peer.transport.write(self.f_wrap_message('R1', helper.json_encode(z)))
        # score = self.chain.score(stake_address=self.chain.mining_address,
        #                         reveal_one=z['reveal_one'],
        #                         balance=self.chain.block_chain_buffer.get_st_balance(self.chain.mining_address, blocknumber),
        #                         seed=epoch_seed)
        if not y:
            self.chain.stake_reveal_one.append([z['stake_address'], z['headerhash'], z['block_number'], z['reveal_one'],
                                                z['weighted_hash'],
                                                z['vote_hash']])  # don't forget to store our reveal in stake_reveal_one

        return z['reveal_one']  # , z['block_number']

    def send_last_stake_reveal_one(self):
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('R1', helper.json_encode(self.last_reveal_one)))

    def ip_geotag_peers(self):
        logger.info('<<<IP geotag broadcast')
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('IP'))
        return

    def ping_peers(self):
        logger.info('<<<Transmitting network PING')
        self.chain.last_ping = time.time()
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('PING'))
        return

    # send POS block to peers..

    def send_stake_block(self, block_obj):
        logger.info('<<<Transmitting POS created block %s %s', str(block_obj.blockheader.blocknumber),
                    block_obj.blockheader.headerhash)
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('S4', helper.json_bytestream(block_obj)))
        return

    # send/relay block to peers

    def send_block_to_peers(self, block, peer_identity=None):
        # logger.info(('<<<Transmitting block: ', block.blockheader.headerhash))
        self.register_and_broadcast('BK', block.blockheader.headerhash, helper.json_bytestream_bk(block))
        return

    def register_and_broadcast(self, msg_type, msg_hash, msg_json):
        self.master_mr.register(msg_hash, msg_json, msg_type)
        msg_hash = sha256(str(msg_hash))
        data = {'hash': msg_hash,
                'type': msg_type}

        for peer in self.peer_connections:
            if msg_hash in self.master_mr.hash_peer:
                if peer in self.master_mr.hash_peer[msg_hash]:
                    continue
            peer.transport.write(self.f_wrap_message('MR', helper.json_encode(data)))

    # request transaction_pool from peers

    def get_tx_pool_from_peers(self):
        logger.info('<<<Requesting TX pool from peers..')
        for peer in self.peer_connections:
            peer.transport.write(self.f_wrap_message('RT'))
        return

    # connection functions

    def connect_peers(self):
        logger.info('<<<Reconnecting to peer list:')
        for peer in self.peer_addresses:
            reactor.connectTCP(peer, 9000, self)

    def clientConnectionLost(self, connector, reason):  # try and reconnect
        # logger.info(( 'connection lost: ', reason, 'trying reconnect'
        # connector.connect()
        return

    def clientConnectionFailed(self, connector, reason):
        # logger.info(( 'connection failed: ', reason
        return

    def startedConnecting(self, connector):
        # logger.info(( 'Started to connect.', connector
        return

    # FIXME: Temporarily moving here
    def load_peer_addresses(self):
        if os.path.isfile(self.peers_path) is True:
            logger.info('Opening peers.dat')
            with open(self.peers_path, 'r') as my_file:
                self.peer_addresses = pickle.load(my_file)
        else:
            logger.info('Creating peers.dat')
            with open(self.peers_path, 'w+') as my_file:
                pickle.dump(config.user.peer_list, my_file)
                self.peer_addresses = config.user.peer_list

        logger.info('Known Peers: %s', self.peer_addresses)

    def update_peer_addresses(self, peer_addresses):
        self.peer_addresses = peer_addresses
        with open(self.peers_path, "w+") as myfile:
            pickle.dump(self.peer_addresses, myfile)

