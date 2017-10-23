# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import json
import struct
import time

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone
from google.protobuf.json_format import MessageToJson, Parse

from pyqrllib.pyqrllib import bin2hstr, hstr2bin
from qrl.core import config, logger, fork
from qrl.core.block import Block
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.node import NodeState
from qrl.core.nstate import NState
from qrl.core.Transaction import DuplicateTransaction, Transaction
from qrl.core.processors.TxnProcessor import TxnProcessor
from qrl.generated import qrl_pb2
from queue import PriorityQueue


class P2PProtocol(Protocol):
    def __init__(self):
        # TODO: Comment with some names the services
        self.service = {'MR': self.MR,  # Message Receipt
                        'SFM': self.SFM,  # Send Full Message
                        'TX': self.TX,  # Transaction
                        'ST': self.ST,  # Stake Transaction
                        'DST': self.DST, # Destake Transaction
                        'DT': self.DT,  # Duplicate Transaction
                        'BM': self.BM,  # Block Height Map
                        'BK': self.BK,  # Block
                        'PBB': self.PBB,  # Push Block Buffer
                        'PB': self.PB,  # Push Block
                        'PH': self.PH,  # Push Headerhash
                        'LB': self.LB,  # Last Block
                        'FMBH': self.FMBH,  # Fetch maximum block height
                        'PMBH': self.PMBH,  # Push Maximum Block Height
                        'MB': self.MB,  # Maximum Block Height
                        'CB': self.CB,  # Check Block Height
                        'BN': self.BN,  # Block Number
                        'FB': self.FB,  # Fetch request for block
                        'FH': self.FH,  # Fetch block header hash
                        'PONG': self.PONG,  # Ping-Pong
                        'PL': self.PL,  # Peers List
                        'RT': self.RT,  # Transaction pool to peer
                        'PE': self.PE,  # Peers (get a list of connected peers)
                        'VE': self.VE,  # Version
                        'IP': self.IP,  # Get IP (geotagging?)
                        'FBHL': self.FBHL,  # Fetch Blockheaderhash List
                        'PBHL': self.PBHL,  # Push Blockheaderhash List
                        'EBHL': self.EBHL,  # Evaluate Blockheaderhash List
                        'resend_SFM': self.resend_SFM  # resend Block from the point of fork
                        }
        self.buffer = b''
        self.messages = []
        self.conn_identity = None
        self.blockheight = None
        self.version = ''
        self.blocknumber_headerhash = {}
        self.last_requested_blocknum = None
        self.fetch_tried = 0
        self.fork_timestamp = 0
        self.disconnect_callLater = None
        self.ping_callLater = None

    def parse_msg(self, data):
        try:
            jdata = json.loads(data.decode())
        except Exception as e:
            logger.warning("parse_msg [json] %s", e)
            logger.exception(e)
            return

        func_name = jdata['type']

        if func_name not in self.service:
            return

        func = self.service[func_name]
        try:
            if 'data' in jdata:
                func(jdata['data'])
            else:
                func()
        except Exception as e:
            logger.debug("executing [%s] by %s", func_name, self.conn_identity)
            logger.exception(e)

    def FBHL(self):
        """
        Fetch Block Headerhash List
        :return:
        """
        self.transport.write(self.wrap_message('PBHL', self.factory.chain.block_chain_buffer.height()))
        self.fork_height = self.factory.chain.block_chain_buffer.height()
        self.fork_timestamp = time.time()
        logger.debug('-->>FBHL called')

    def PBHL(self, blocknumber=None):
        """
        Push Block Headerhash List
        :return:
        """
        if not blocknumber:
            logger.debug('PBHL blocknumber None by %s', self.conn_identity)
            return

        logger.debug('PBHL received by %s', self.conn_identity)
        blocknum_headerhash = qrl_pb2.BlockMetaDataList()
        for blocknum in range(blocknumber - config.dev.reorg_limit, blocknumber + 1):
            blockmetadata = qrl_pb2.BlockMetaData()
            block = self.factory.chain.block_chain_buffer.get_block_n(blocknum)
            if not block:
                break
            blockmetadata.block_number = blocknum
            blockmetadata.hash_header = block.blockheader.headerhash
            blocknum_headerhash.block_number_hashes.extend([blockmetadata])

        self.transport.write(self.wrap_message('EBHL', MessageToJson(blocknum_headerhash)))
        self.fork_timestamp = time.time()

    def EBHL(self, data):
        """
        Evaluate Block Headerhash List
        :return:
        """
        logger.debug('EBHL received by %s', self.conn_identity)
        if time.time() - self.fork_timestamp > 120:  # Reject if replied after 2 minutes
            return

        blocknum_headerhash = qrl_pb2.BlockMetaDataList()
        Parse(data, blocknum_headerhash)

        last_matching_blocknum = None
        for blockmetadata in blocknum_headerhash.block_number_hashes:
            if blockmetadata.block_number > self.factory.chain.block_chain_buffer.height():
                return

            block = self.factory.chain.block_chain_buffer.get_block_n(blockmetadata.block_number)

            if blockmetadata.hash_header != block.blockheader.headerhash:
                if last_matching_blocknum:
                    # Check if the forked point is within chainbuffer
                    if blockmetadata.block_number in self.factory.chain.block_chain_buffer.blocks:
                        logger.debug('Calling peer resend_SFM %s', blockmetadata.block_number)
                        self.transport.write(self.wrap_message('resend_SFM', blockmetadata.block_number))
                return
            last_matching_blocknum = blockmetadata.block_number

        self.fork_timestamp = time.time()

    def resend_SFM(self, blocknum):
        logger.debug('Resending SFM %s', blocknum)
        block_chain_buffer = self.factory.chain.block_chain_buffer
        if blocknum > block_chain_buffer.height():
            return

        max_blocknum = min(block_chain_buffer.height()+1, blocknum+config.dev.blocks_per_epoch)
        for blocknumber in range(blocknum, max_blocknum):
            block = block_chain_buffer.get_block_n(blocknumber)

            data = qrl_pb2.MR()
            data.hash = block.blockheader.headerhash
            data.type = 'BK'

            if block.blockheader.blocknumber > 1:
                data.reveal_hash = block.blockheader.reveal_hash

            self.SFM(MessageToJson(data))

        return

    def MR(self, data):
        """
        Message Receipt
        This function accepts message receipt from peer,
        checks if the message hash already been received or not.
        In case its a already received message, it is ignored.
        Otherwise the request is made to get the full message.
        :return:
        """
        mr_data = qrl_pb2.MR()
        try:
            Parse(data, mr_data)
        except Exception as e:  # Disconnect peer not following protocol
            logger.debug('Disconnected peer %s not following protocol in MR %s', self.conn_identity, e)
            self.transport.loseConnection()
        msg_hash = mr_data.hash

        if mr_data.type not in MessageReceipt.allowed_types:
            return

        if mr_data.type in ['TX'] and self.factory.nodeState.state != NState.synced:
            return

        if mr_data.type == 'TX' and len(self.factory.chain.pending_tx_pool) >= config.dev.transaction_pool_size:
            logger.warning('TX pool size full, incoming tx dropped. mr hash: %s', bin2hstr(msg_hash))
            return

        if mr_data.type == 'ST' and self.factory.chain.height() > 1 and self.factory.nodeState.state != NState.synced:
            return

        if self.factory.master_mr.contains(msg_hash, mr_data.type):
            return

        self.factory.master_mr.add_peer(msg_hash, mr_data.type, self, mr_data)

        if self.factory.master_mr.is_callLater_active(msg_hash):  # Ignore if already requested
            return

        if mr_data.type == 'BK':
            block_chain_buffer = self.factory.chain.block_chain_buffer

            if not block_chain_buffer.verify_BK_hash(mr_data, self.conn_identity):
                if block_chain_buffer.is_duplicate_block(blocknum=mr_data.block_number,
                                                         prev_blockheaderhash=tuple(mr_data.prev_headerhash),
                                                         stake_selector=mr_data.stake_selector):
                    self.factory.RFM(mr_data)
                elif mr_data.block_number > self.factory.chain.block_chain_buffer.height() - config.dev.reorg_limit:
                    self.FBHL()
                return

            blocknumber = mr_data.block_number
            target_blocknumber = block_chain_buffer.bkmr_tracking_blocknumber(self.factory.pos.ntp)
            if target_blocknumber != self.factory.bkmr_blocknumber:
                self.factory.bkmr_blocknumber = target_blocknumber
                del self.factory.bkmr_priorityq
                self.factory.bkmr_priorityq = PriorityQueue()

            if blocknumber != target_blocknumber or blocknumber == 1:
                self.factory.RFM(mr_data)
                return

            score = block_chain_buffer.score_BK_hash(mr_data)
            self.factory.bkmr_priorityq.put((score, msg_hash))

            if not self.factory.bkmr_processor.active():
                self.factory.bkmr_processor = reactor.callLater(1, self.factory.select_best_bkmr)

            return

        self.factory.RFM(mr_data)

    def SFM(self, data):  # Send full message
        """
        Send Full Message
        This function serves the request made for the full message.
        :return:
        """
        mr_data = qrl_pb2.MR()
        Parse(data, mr_data)
        msg_hash = mr_data.hash
        msg_type = mr_data.type

        if not self.factory.master_mr.contains(msg_hash, msg_type):
            return

        # Sending message from node, doesn't guarantee that peer has received it.
        # Thus requesting peer could re request it, may be ACK would be required
        self.transport.write(self.wrap_message(msg_type, self.factory.master_mr.hash_msg[msg_hash].msg))

    def TX(self, data):  # tx received..
        """
        Transaction
        Executed whenever a new TX type message is received.
        :return:
        """
        self.recv_tx(data)
        return

    def ST(self, data):
        """
        Stake Transaction
        This function processes whenever a Transaction having
        subtype ST is received.
        :return:
        """
        try:
            st = Transaction.from_json(data)
        except Exception as e:
            logger.error('st rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(st.get_message_hash(), self):
            return

        if len(self.factory.chain.m_blockchain) == 1 and \
                                st.activation_blocknumber > self.factory.chain.height() + config.dev.blocks_per_epoch:
            return

        height = self.factory.chain.block_chain_buffer.height() + 1
        stake_validators_list = self.factory.chain.block_chain_buffer.get_stake_validators_list(height)

        if st.txfrom in stake_validators_list.future_stake_addresses:
            logger.debug('P2P dropping st as staker is already in future_stake_address %s', st.txfrom)
            return

        if st.txfrom in stake_validators_list.sv_list:
            expiry = stake_validators_list.sv_list[st.txfrom].activation_blocknumber + config.dev.blocks_per_epoch
            if st.activation_blocknumber < expiry:
                logger.debug('P2P dropping st txn as it is already active for the given range %s', st.txfrom)
                return

        if st.activation_blocknumber > height + config.dev.blocks_per_epoch:
            logger.debug('P2P dropping st as activation_blocknumber beyond limit')
            return False

        for t in self.factory.chain.transaction_pool:
            if st.get_message_hash() == t.get_message_hash():
                return

        tx_state = self.factory.chain.block_chain_buffer.get_stxn_state(
            blocknumber=self.factory.chain.block_chain_buffer.height() + 1,
            addr=st.txfrom)
        if st.validate() and st.validate_extended(tx_state=tx_state):
            self.factory.chain.add_tx_to_pool(st)
        else:
            logger.warning('>>>ST %s invalid state validation failed..', bin2hstr(tuple(st.hash)))
            return

        self.factory.register_and_broadcast('ST', st.get_message_hash(), st.to_json())
        return

    def DST(self, data):
        """
        Destake Transaction
        This function processes whenever a Transaction having
        subtype DESTAKE is received.
        :return:
        """
        try:
            destake_txn = Transaction.from_json(data)
        except Exception as e:
            logger.error('de stake rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(destake_txn.get_message_hash(), self):
            return

        for t in self.factory.chain.transaction_pool:
            if destake_txn.get_message_hash() == t.get_message_hash():
                return

        txfrom = destake_txn.txfrom
        height = self.factory.chain.block_chain_buffer.height() + 1
        stake_validators_list = self.factory.chain.block_chain_buffer.get_stake_validators_list(height)

        if txfrom not in stake_validators_list.sv_list and txfrom not in stake_validators_list.future_stake_addresses:
            logger.debug('P2P Dropping destake txn as %s not found in stake validator list', txfrom)
            return

        tx_state = self.factory.chain.block_chain_buffer.get_stxn_state(
            blocknumber=height,
            addr=txfrom)
        if destake_txn.validate() and destake_txn.validate_extended(tx_state=tx_state):
            self.factory.chain.add_tx_to_pool(destake_txn)
        else:
            logger.debug('>>>Destake %s invalid state validation failed..', txfrom)
            return

        self.factory.register_and_broadcast('DST', destake_txn.get_message_hash(), destake_txn.to_json())
        return

    def DT(self, data):
        """
        Duplicate Transaction
        This function processes whenever a Transaction having
        subtype DT is received.
        :return:
        """
        try:
            duplicate_txn = DuplicateTransaction().from_json(data)
        except Exception as e:
            logger.error('DT rejected')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(duplicate_txn.get_message_hash(), self):
            return

        if duplicate_txn.get_message_hash() in self.factory.chain.duplicate_tx_pool:
            return

        # TODO: State validate for duplicate_txn is pending
        if duplicate_txn.validate():
            self.factory.chain.add_tx_to_duplicate_pool(duplicate_txn)
        else:
            logger.debug('>>>Invalid DT txn %s', bin2hstr(duplicate_txn.get_message_hash()))
            return

        self.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())
        return

    def BM(self, data=None):  # blockheight map for synchronisation and error correction prior to POS cycle resync..
        """
        Blockheight Map
        Simply maps the peer with their respective blockheight.
        If no data is provided in parameter, the node sends its 
        own current blockheight. 
        :return:
        """
        if not data:
            logger.info('<<< Sending block_map %s', self.transport.getPeer().host)

            z = {'block_number': self.factory.chain.m_blockchain[-1].blockheader.blocknumber,
                 'headerhash': self.factory.chain.m_blockchain[-1].blockheader.headerhash}

            self.transport.write(self.wrap_message('BM', json.dumps(z)))
            return
        else:
            logger.info('>>> Receiving block_map')
            z = json.loads(data)
            block_number = z['block_number']
            headerhash = z['headerhash'].encode('latin1')

            i = [block_number, headerhash, self.transport.getPeer().host]
            logger.info('%s', i)
            if i not in self.factory.chain.blockheight_map:
                self.factory.chain.blockheight_map.append(i)
            return

    def BK(self, data):  # block received
        """
        Block
        This function processes any new block received.
        :return:
        """
        try:
            block = Block.from_json(data)
        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.transport.getPeer().host)
            logger.exception(e)
            return

        logger.info('>>>Received block from %s %s %s',
                    self.conn_identity,
                    block.blockheader.blocknumber,
                    block.blockheader.stake_selector)

        if not self.factory.master_mr.isRequested(block.blockheader.headerhash, self, block):
            return

        block_chain_buffer = self.factory.chain.block_chain_buffer

        if block_chain_buffer.is_duplicate_block(blocknum=block.blockheader.blocknumber,
                                                 prev_blockheaderhash=block.blockheader.prev_blockheaderhash,
                                                 stake_selector=block.blockheader.stake_selector):
            logger.info('Found duplicate block #%s by %s',
                        block.blockheader.blocknumber,
                        block.blockheader.stake_selector)
            coinbase_txn = block.transactions[0]

            sv_list = self.factory.chain.block_chain_buffer.stake_list_get(block.blockheader.blocknumber)
            if coinbase_txn.validate_extended(sv_list=sv_list, blockheader=block.blockheader):
                self.factory.master_mr.register_duplicate(block.blockheader.headerhash)
                block2 = block_chain_buffer.get_block_n(block.blockheader.blocknumber)

                duplicate_txn = DuplicateTransaction().create(block1=block, block2=block2)
                if duplicate_txn.validate():
                    self.factory.chain.add_tx_to_duplicate_pool(duplicate_txn)
                    self.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())

        self.factory.pos.pre_block_logic(block)
        self.factory.master_mr.register(block.blockheader.headerhash, data, 'BK')
        return

    def isNoMoreBlock(self, data):
        if type(data) == int:
            blocknumber = data
            if blocknumber != self.last_requested_blocknum:
                return True
            try:
                reactor.download_monitor.cancel()
            except:
                pass
            self.factory.pos.update_node_state(NState.synced)
            return True
        return False

    def PBB(self, data):
        """
        Push Block Buffer
        This function executes while syncing block from other peers.
        Blocks received by this function, directly added into
        chain.block_chain_buffer.
        :return:
        """
        self.factory.pos.last_pb_time = time.time()
        try:
            if self.isNoMoreBlock(data):
                return

            block = Block.from_json(data)
            blocknumber = block.blockheader.blocknumber

            if blocknumber != self.last_requested_blocknum:
                logger.info('Blocknumber not found in pending_blocks %s %s', blocknumber, self.conn_identity)
                return

            logger.info('>>>Received Block #%s', block.blockheader.blocknumber)

            status = self.factory.chain.block_chain_buffer.add_block(block)
            if type(status) == bool and not status:
                logger.info("[PBB] Failed to add block by add_block, re-requesting the block #%s", blocknumber)
                logger.info('Skipping one block')

            try:
                reactor.download_block.cancel()
            except Exception:
                pass

            # Below code is to stop downloading, once we see that we reached to blocknumber that are in pending_blocks
            # This could be exploited by sybil node, to send blocks in pending_blocks in order to disrupt downloading
            # TODO: requires a better fix
            if len(self.factory.chain.block_chain_buffer.pending_blocks) > 0 and min(
                    self.factory.chain.block_chain_buffer.pending_blocks.keys()) == blocknumber:
                self.factory.chain.block_chain_buffer.process_pending_blocks()
                return
            self.factory.pos.randomize_block_fetch(blocknumber + 1)
        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.transport.getPeer().host)
            logger.exception(e)
        return

    def PB(self, data):
        """
        Push Block
        This function processes requested blocks received while syncing.
        Block received under this function are directly added to the main
        chain i.e. chain.m_blockchain
        It is expected to receive only one block for a given blocknumber.
        :return:
        """
        self.factory.pos.last_pb_time = time.time()
        try:
            if self.isNoMoreBlock(data):
                return

            block = Block.from_json(data)

            blocknumber = block.blockheader.blocknumber
            logger.info('>>> Received Block #%d', blocknumber)
            if blocknumber != self.last_requested_blocknum:
                logger.warning('Did not match %s %s', self.last_requested_blocknum, self.conn_identity)
                return

            if blocknumber > self.factory.chain.height():
                if not self.factory.chain.add_block_mainchain(block):
                    logger.warning('PB failed to add block to mainchain')
                    return

            try:
                reactor.download_monitor.cancel()
            except Exception as e:
                logger.warning("PB: %s", e)

            self.factory.pos.randomize_block_fetch(blocknumber + 1)

        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.transport.getPeer().host)
            logger.exception(e)
        return

    def PH(self, data):
        """
        Push Headerhash
        :return:
        """
        if self.factory.nodeState.state == NState.forked:
            fork.verify(data, self.conn_identity, self.chain, self.randomize_headerhash_fetch)
        else:
            mini_block = json.loads(data)
            self.blocknumber_headerhash[mini_block['blocknumber']] = hstr2bin(mini_block['headerhash'])
        return

    def LB(self):  # request for last block to be sent
        """
        Last BLock
        Sends the last block from the main chain.
        :return:
        """
        logger.info('<<<Sending last block %s %s bytes to node %s', self.factory.chain.m_blockheight(),
                    str(len(self.factory.chain.m_get_last_block().to_json())),
                    self.transport.getPeer().host)

        self.transport.write(self.wrap_message('BK', self.factory.chain.m_get_last_block()).to_json())
        return

    def FMBH(self):  # Fetch Maximum Blockheight and Headerhash
        """
        Fetch Maximum Blockheight and HeaderHash
        Serves the fetch request for maximum blockheight & headerhash
        Sends the current blockheight and the headerhash of the 
        last block in mainchain.
        :return:
        """
        if self.factory.pos.nodeState.state != NState.synced:
            return
        logger.info('<<<Sending blockheight and headerhash to: %s %s', self.transport.getPeer().host, str(time.time()))
        data = qrl_pb2.BlockMetaData()
        data.hash_header = self.factory.chain.m_blockchain[-1].blockheader.headerhash
        data.block_number = self.factory.chain.m_blockchain[-1].blockheader.blocknumber

        self.transport.write(self.wrap_message('PMBH', MessageToJson(data)))
        return

    def PMBH(self, raw_data):  # Push Maximum Blockheight and Headerhash
        """
        Push Maximum Blockheight and Headerhash
        Function processes, received maximum blockheight and headerhash.
        :return:
        """
        data = qrl_pb2.BlockMetaData()
        Parse(raw_data, data)

        tmp = data.hash_header

        if self.conn_identity in self.factory.pos.fmbh_allowed_peers:
            self.factory.pos.fmbh_allowed_peers[self.conn_identity] = data
            if tmp not in self.factory.pos.fmbh_blockhash_peers:
                self.factory.pos.fmbh_blockhash_peers[tmp] = {'blocknumber': data.block_number,
                                                              'peers': []}
            self.factory.pos.fmbh_blockhash_peers[tmp]['peers'].append(self)

    def MB(self):  # we send with just prefix as request..with CB number and blockhash as answer..
        """
        Maximum Blockheight
        Sends maximum blockheight of the mainchain.
        :return:
        """
        logger.info('<<<Sending blockheight to: %s %s', self.transport.getPeer().host, str(time.time()))
        self.send_m_blockheight_to_peer()
        return

    def CB(self, raw_data):
        """
        Check Blockheight
        :return:
        # FIXME: This test grew too much. Convert doctest into unit test using mocks
        >>> from collections import namedtuple, defaultdict
        >>> from qrl.generated import qrl_pb2
        >>> p=P2PProtocol()
        >>> Transport = namedtuple("Transport", "getPeer write")
        >>> Peer = namedtuple("Peer", "host port")
        >>> Factory = namedtuple("Factory", "peers_blockheight chain nodeState")
        >>> Chain = namedtuple("Chain", "m_blockchain m_blockheight")
        >>> def getPeer():
        ...     return Peer("host", 1234)
        >>> message = None
        >>> def write(msg):
        ...     global message
        ...     message = msg
        >>> def m_blockheight():
        ...     return 0
        >>> p.transport = Transport(getPeer, write)
        >>> p.chain = Chain([], m_blockheight)
        >>> tmp = NodeState()
        >>> tmp.state = NState.synced
        >>> p.factory = Factory(defaultdict(), p.chain, tmp)
        >>> data = qrl_pb2.BlockMetaData()
        >>> data.block_number = 3
        >>> data.hash_header = bytes((53, 130, 168, 57, 183, 215, 120, 178, 209, 30, 194, 223, 221, 58, 72, 124, 62, 148, 110, 81, 19, 189, 27, 243, 218, 87, 217, 203, 198, 97, 84, 19))
        >>> jsonData = MessageToJson(data)
        >>> p.CB(jsonData)
        """
        data = qrl_pb2.BlockMetaData()

        try:
            Parse(raw_data, data)
        except Exception as e:  # Disconnect peers not following protocol
            logger.debug('Disconnected peer %s not following protocol in MR %s', self.conn_identity, e)
            self.transport.loseConnection()

        block_number = data.block_number
        headerhash = data.hash_header

        tmp = "{}:{}".format(self.transport.getPeer().host, self.transport.getPeer().port)
        self.factory.peers_blockheight[tmp] = data.block_number

        self.blockheight = block_number
        logger.info('>>>Blockheight from: %s blockheight: %s local blockheight: %s %s',
                    self.transport.getPeer().host, block_number,
                    self.factory.chain.m_blockheight(), str(time.time()))

        if self.factory.nodeState.state == NState.syncing:
            return

        if block_number == self.factory.chain.m_blockheight():
            # if self.factory.chain.m_blockchain[block_number].blockheader.headerhash != headerhash:
            if self.factory.chain.m_get_block(block_number).blockheader.headerhash != headerhash:
                logger.warning('>>> headerhash mismatch from %s', self.transport.getPeer().host)

                # initiate fork recovery and protection code here..
                # call an outer function which sets a flag and scrutinises the chains from all connected hosts to see what is going on..
                # again need to think this one through in detail..
                return

        if block_number > self.factory.chain.m_blockheight():
            return

        if self.factory.chain.height() == 0 and self.factory.genesis == 0:
            # set the flag so that no other Protocol instances trigger the genesis stake functions..
            self.factory.genesis = 1
            logger.info('genesis pos countdown to block 1 begun, 60s until stake tx circulated..')
            reactor.callLater(1, self.factory.pos.pre_pos_1)
            return

        # connected to multiple hosts and already passed through..
        elif self.factory.chain.height() == 1 and self.factory.genesis == 1:
            return

    def BN(self, data):  # request for block (n)
        """Block(n)
        Sends the nth block from mainchain.
        :return:
        """
        if int(data) <= self.factory.chain.m_blockheight():
            logger.info('<<<Sending block number %s %s bytes to node: %s', int(data),
                        len(self.factory.chain.m_get_block(int(data)).to_json()),
                        self.transport.getPeer().host)
            self.transport.write(
                self.wrap_message('BK', self.factory.chain.m_get_block(int(data))).to_json())
        else:
            if int(data) >= self.factory.chain.m_blockheight():
                logger.info('BN for a blockheight greater than local chain length..')
            else:
                logger.info('BN request without valid block number %s - closing connection', str(data))
                self.transport.loseConnection()
        return

    def FB(self, data):  # Fetch Request for block
        """
        Fetch Block
        Sends the request for the block.
        :return:
        """
        data = int(data)
        logger.info(' Request for %s by %s', data, self.conn_identity)
        if 0 < data <= self.factory.chain.block_chain_buffer.height():
            self.factory.chain.block_chain_buffer.send_block(data, self.transport, self.wrap_message)
        else:
            self.transport.write(self.wrap_message('PB', data))
            if data > self.factory.chain.height():
                logger.info('FB for a blocknumber is greater than the local chain length..')
                return
            logger.info(' Send for blocmnumber #%s to %s', data, self.conn_identity)
        return

    def FH(self, data):  # Fetch Block Headerhash
        """
        Fetch Block Headerhash
        Sends the request for the blockheaderhash of a given blocknumber.
        :return:
        """
        data = int(data)
        if 0 < data <= self.factory.chain.height():
            mini_block = {}
            logger.info('<<<Pushing block headerhash of block number %s to node: %s',
                        str(data), self.transport.getPeer().host)
            mini_block['headerhash'] = self.factory.chain.m_get_block(data).blockheader.headerhash
            mini_block['blocknumber'] = data
            self.transport.write(self.wrap_message('PH', json.dumps(mini_block)))
        else:
            if data > self.factory.chain.height():
                logger.info('FH for a blocknumber is greater than the local chain length..')
        return

    def PO(self, data):
        """
        Pong
        :return:
        """
        if data[0:2] == 'NG':
            y = 0
            for entry in self.factory.chain.ping_list:
                if entry['node'] == self.transport.getPeer().host:
                    entry['ping (ms)'] = (time.time() - self.chain.last_ping) * 1000
                    y = 1
            if y == 0:
                self.factory.chain.ping_list.append({'node': self.transport.getPeer().host,
                                                     'ping (ms)': (time.time() - self.factory.chain.last_ping) * 1000})

    def PING(self):
        """
        Ping
        :return:
        """
        self.transport.write(self.wrap_message('PONG'))
        logger.debug('Sending PING to %s', self.conn_identity)
        return

    def PONG(self):
        """
        Pong
        :return:
        """
        self.disconnect_callLater.reset(config.user.ping_timeout)
        if self.ping_callLater.active():
            self.ping_callLater.cancel()
        self.ping_callLater = reactor.callLater(config.user.ping_frequency, self.PING)
        logger.debug('Received PONG from %s', self.conn_identity)
        return

    def PL(self, data):  # receiving a list of peers to save into peer list..
        """
        Peers List
        :return:
        """
        self.recv_peers(data)

    def RT(self):
        """
        Transaction_pool to peer
        :return:
        """
        for t in self.factory.chain.transaction_pool:
            self.f.send_tx_to_peers(t)
        return

    def PE(self):  # get a list of connected peers..need to add some ddos and type checking proteection here..
        """
        Peers
        Sends the list of all connected peers.
        :return:
        """
        self.get_peers()
        return

    def VE(self, data=None):
        """
        Version
        If data is None then sends the version & genesis_prev_headerhash.
        Otherwise, process the content of data and incase of non matching,
        genesis_prev_headerhash, it disconnects the odd peer.
        :return:
        """
        if not data:
            version_details = {
                'version': config.dev.version,
                'genesis_prev_headerhash': config.dev.genesis_prev_headerhash
            }
            self.transport.write(self.wrap_message('VE', json.dumps(version_details)))
        else:
            try:
                data = json.loads(data)
                self.version = str(data['version'])
                logger.info('%s version: %s | genesis prev_headerhash %s',
                            self.transport.getPeer().host,
                            data['version'],
                            data['genesis_prev_headerhash'])

                if data['genesis_prev_headerhash'] == config.dev.genesis_prev_headerhash:
                    return
                logger.warning('%s genesis_prev_headerhash mismatch', self.conn_identity)
                logger.warning('Expected: %s', config.dev.genesis_prev_headerhash)
                logger.warning('Found: %s', data['genesis_prev_headerhash'])
            except Exception as e:
                logger.error('Peer Caused Exception %s', self.conn_identity)
                logger.exception(e)

            self.transport.loseConnection()

        return

    def IP(self, data):  # fun feature to allow geo-tagging on qrl explorer of test nodes..reveals IP so optional..
        """
        IP
        If data is None, node sends its own IP.
        Otherwise, append the received IP into ip_list
        and also broadcast it to all other connected peers
        :return:
        """
        if not data:
            if self.factory.ip_geotag == 1:
                for peer in self.factory.peers:
                    if peer != self:
                        peer.transport.write(self.wrap_message('IP', self.transport.getHost().host))
        else:
            if data not in self.factory.chain.ip_list:
                self.factory.chain.ip_list.append(data)
                for peer in self.factory.peers:
                    if peer != self:
                        peer.transport.write(self.wrap_message('IP', self.transport.getHost().host))

        return

    def recv_peers(self, json_data):
        """
        Receive Peers
        Received peers list is saved.
        :return:
        """
        if not config.user.enable_peer_discovery:
            return
        data = json.loads(json_data)
        new_ips = []
        for ip in data:
            if ip not in new_ips:
                new_ips.append(ip)

        peer_addresses = self.factory.node.peer_addresses
        logger.info('%s peers data received: %s', self.transport.getPeer().host, new_ips)
        for node in new_ips:
            if node not in peer_addresses:
                if node != self.transport.getHost().host:
                    peer_addresses.append(node)
                    reactor.connectTCP(node, 9000, self.factory)

        self.factory.node.update_peer_addresses(peer_addresses)
        return

    def get_latest_block_from_connection(self):
        """
        Get Latest Block
        Sends the request for the last block in the mainchain.
        :return:
        """
        logger.info('<<<Requested last block from %s', self.transport.getPeer().host)
        self.transport.write(self.wrap_message('LB'))
        return

    def get_m_blockheight_from_connection(self):
        """
        Get blockheight
        Sends the request to all peers to send their mainchain max blockheight.
        :return:
        >>> from collections import namedtuple
        >>> p=P2PProtocol()
        >>> Transport = namedtuple("Transport", "getPeer write")
        >>> Peer = namedtuple("Peer", "host")
        >>> def getPeer():
        ...     return Peer("host")
        >>> message = None
        >>> def write(msg):
        ...     global message
        ...     message = msg
        >>> p.transport = Transport(getPeer, write)
        >>> p.get_m_blockheight_from_connection()
        >>> bin2hstr(message)
        'ff00003030303030303065007b2274797065223a20224d42227d0000ff'
        """
        logger.info('<<<Requesting blockheight from %s', self.transport.getPeer().host)
        msg = self.wrap_message('MB')
        self.transport.write(msg)

    def send_m_blockheight_to_peer(self):
        """
        Send mainchain blockheight to peer
        Sends the mainchain maximum blockheight request.
        :return:
        """
        data = qrl_pb2.BlockMetaData()
        data.hash_header = self.factory.chain.m_blockchain[-1].blockheader.headerhash

        if len(self.factory.chain.m_blockchain):
            data.block_number = self.factory.chain.m_blockchain[-1].blockheader.blocknumber
        self.transport.write(self.wrap_message('CB', MessageToJson(data)))
        return

    def get_version(self):
        """
        Get Version
        Sends request for the version.
        :return:
        """
        logger.info('<<<Getting version %s', self.transport.getPeer().host)
        self.transport.write(self.wrap_message('VE'))
        return

    def get_peers(self):
        """
        Get Peers
        Sends the peers list.
        :return:
        """
        logger.info('<<<Sending connected peers to %s', self.transport.getPeer().host)
        peers_list = []
        for peer in self.factory.peer_connections:
            peers_list.append(peer.transport.getPeer().host)
        self.transport.write(self.wrap_message('PL', json.dumps(peers_list)))
        return

    def get_block_n(self, n):
        """
        Get Block n
        Sends request for the block number n.
        :return:
        """
        logger.info('<<<Requested block: %s from %s', n, self.transport.getPeer().host)
        self.transport.write(self.wrap_message('BN', str(n)))
        return

    def fetch_block_n(self, n):
        """
        Fetch Block n
        Sends request for the block number n.
        :return:
        """
        if self.last_requested_blocknum != n:
            self.fetch_tried = 0
        self.fetch_tried += 1  # TODO: remove from target_peers if tried is greater than x
        self.last_requested_blocknum = n
        logger.info('<<<Fetching block: %s from %s', n, self.conn_identity)
        self.transport.write(self.wrap_message('FB', str(n)))
        return

    def fetch_FMBH(self):
        """
        Fetch Maximum Block Height
        Sends request for the maximum blockheight.
        :return:
        """
        logger.info('<<<Fetching FMBH from : %s', self.conn_identity)
        self.transport.write(self.wrap_message('FMBH'))

    def fetch_headerhash_n(self, n):
        """
        Fetch Headerhash n
        Sends request for the headerhash of blocknumber n.
        :return:
        """
        logger.info('<<<Fetching headerhash of block: %s from %s', n, self.conn_identity)
        self.transport.write(self.wrap_message('FH', str(n)))
        return

    MSG_INITIATOR = bytearray(b'\xff\x00\x00')
    MSG_TERMINATOR = bytearray(b'\x00\x00\xff')

    @staticmethod
    def wrap_message(mtype, data=None):
        """
        :param mtype:
        :type mtype: str
        :param data:
        :type data: Union[None, str, None, None, None, None, None, None, None, None, None]
        :return:
        :rtype: str

        >>> answer = bin2hstr(P2PProtocol.wrap_message('TESTKEY_1234', 12345))
        >>> answer == 'ff00003030303030303237007b2264617461223a2031323334352c202274797065223a2022544553544b45595f31323334227d0000ff' or answer == 'ff00003030303030303237007b2274797065223a2022544553544b45595f31323334222c202264617461223a2031323334357d0000ff'
        True
        """
        # FIXME: Move this to protobuf
        jdata = {'type': mtype}
        if data:
            jdata['data'] = data

        str_data = json.dumps(jdata)

        # FIXME: struct.pack may result in endianness problems
        str_data_len = bin2hstr(struct.pack('>L', len(str_data)))

        tmp = b''
        tmp += P2PProtocol.MSG_INITIATOR
        tmp += str_data_len.encode()
        tmp += bytearray(b'\x00')
        tmp += str_data.encode()
        tmp += P2PProtocol.MSG_TERMINATOR

        return tmp

    def clean_buffer(self, reason=None, upto=None):
        if reason:
            logger.info('%s', reason)
        if upto:
            self.buffer = self.buffer[upto:]  # Clean buffer till the value provided in upto
        else:
            self.buffer = b''  # Clean buffer completely

    def parse_buffer(self):
        # FIXME: This parsing/wire protocol needs to be replaced
        """
        :return:
        :rtype: bool

        >>> p=P2PProtocol()
        >>> p.buffer = bytes(hstr2bin("ff00003030303030303237007b2264617461223a2031323334352c202274797065223a2022544553544b45595f31323334227d0000ff"))
        >>> found_message = p.parse_buffer()
        >>> p.messages
        [b'{"data": 12345, "type": "TESTKEY_1234"}']
        """
        # FIXME
        if len(self.buffer) == 0:
            return False

        d = self.buffer.find(P2PProtocol.MSG_INITIATOR)  # find the initiator sequence
        num_d = self.buffer.count(P2PProtocol.MSG_INITIATOR)  # count the initiator sequences

        if d == -1:  # if no initiator sequences found then wipe buffer..
            logger.warning('Message data without initiator')
            self.clean_buffer(reason='Message data without initiator')
            return False

        self.buffer = self.buffer[d:]  # delete data up to initiator

        if len(self.buffer) < 8:  # Buffer is still incomplete as it doesn't have message size
            return False

        try:
            tmp = self.buffer[3:11]
            tmp2 = hstr2bin(tmp.decode())
            tmp3 = bytearray(tmp2)
            m = struct.unpack('>L', tmp3)[0]  # is m length encoded correctly?
        except (UnicodeDecodeError, ValueError):
            logger.info('Peer not following protocol %s', self.conn_identity)
            self.transport.loseConnection()
            return False
        except Exception as e:
            logger.exception(e)
            if num_d > 1:  # if not, is this the only initiator in the buffer?
                self.buffer = self.buffer[3:]
                d = self.buffer.find(P2PProtocol.MSG_INITIATOR)
                self.clean_buffer(reason='Struct.unpack error attempting to decipher msg length, next msg preserved',
                                  upto=d)  # no
                return True
            else:
                self.clean_buffer(reason='Struct.unpack error attempting to decipher msg length..')  # yes
            return False

        if m > config.dev.message_buffer_size:  # check if size is more than 500 KB
            if num_d > 1:
                self.buffer = self.buffer[3:]
                d = self.buffer.find(P2PProtocol.MSG_INITIATOR)
                self.clean_buffer(reason='Size is more than 500 KB, next msg preserved', upto=d)
                return True
            else:
                self.clean_buffer(reason='Size is more than 500 KB')
            return False

        e = self.buffer.find(P2PProtocol.MSG_TERMINATOR)  # find the terminator sequence

        if e == -1:  # no terminator sequence found
            if len(self.buffer) > 12 + m + 3:
                if num_d > 1:  # if not is this the only initiator sequence?
                    self.buffer = self.buffer[3:]
                    d = self.buffer.find(P2PProtocol.MSG_INITIATOR)
                    self.clean_buffer(reason='Message without appropriate terminator, next msg preserved', upto=d)  # no
                    return True
                else:
                    self.clean_buffer(reason='Message without initiator and terminator')  # yes
            return False

        if e != 3 + 9 + m:  # is terminator sequence located correctly?
            if num_d > 1:  # if not is this the only initiator sequence?
                self.buffer = self.buffer[3:]
                d = self.buffer.find(P2PProtocol.MSG_INITIATOR)
                self.clean_buffer(reason='Message terminator incorrectly positioned, next msg preserved', upto=d)  # no
                return True
            else:
                self.clean_buffer(reason='Message terminator incorrectly positioned')  # yes
            return False

        self.messages.append(self.buffer[12:12 + m])  # if survived the above then save the msg into the self.messages
        self.buffer = self.buffer[12 + m + 3:]  # reset the buffer to after the msg
        return True

    def dataReceived(self,
                     data: bytearray) -> None:  # adds data received to buffer. then tries to parse the buffer twice..
        """
        :param data:Message data without initiator
        :return:
        :rtype: None

        >>> from unittest.mock import MagicMock
        >>> p=P2PProtocol()
        >>> p.service['TESTKEY_1234'] = MagicMock(side_effect=(lambda x: x))
        >>> p.dataReceived(bytes(hstr2bin("ff00003030303030303237007b2264617461223a2031323334352c202274797065223a2022544553544b45595f31323334227d0000ff")))
        >>> p.service['TESTKEY_1234'].call_args
        call(12345)
        >>> from unittest.mock import MagicMock
        >>> data = bytearray(hstr2bin('ff00003030303030303065007b2274797065223a20224d42227d0000ffff00003030303030303261007b2264617461223a20225b5c223137322e31382e302e325c225d222c202274797065223a2022504c227d0000ffff00003030303030303065007b2274797065223a20225645227d0000ff'))
        >>> p=P2PProtocol()
        >>> p.service['MB'] = MagicMock()
        >>> p.dataReceived(data)
        >>> print(p.service['MB'].called)
        True
        >>> data = bytearray(hstr2bin('ff00003030303030303065007b2274797065223a20224d42227d0000ffff00003030303030303261007b2274797065223a2022504c222c202264617461223a20225b5c223137322e31382e302e365c225d227d0000ffff00003030303030303065007b2274797065223a20225645227d0000ffff00003030303030306434007b2274797065223a20224342222c202264617461223a20227b5c22626c6f636b5f6e756d6265725c223a20302c205c22686561646572686173685c223a205b35332c203133302c203136382c2035372c203138332c203231352c203132302c203137382c203230392c2033302c203139342c203232332c203232312c2035382c2037322c203132342c2036322c203134382c203131302c2038312c2031392c203138392c2032372c203234332c203231382c2038372c203231372c203230332c203139382c2039372c2038342c2031395d7d227d0000ffff00003030303030303635007b2274797065223a20225645222c202264617461223a20227b5c2267656e657369735f707265765f686561646572686173685c223a205c2243727970746f6e69756d5c222c205c2276657273696f6e5c223a205c22616c7068612f302e3435615c227d227d0000ff'))
        >>> p=P2PProtocol()
        >>> p.service['MB'] = MagicMock()
        >>> p.service['PL'] = MagicMock()
        >>> p.service['VE'] = MagicMock()
        >>> p.service['CB'] = MagicMock()
        >>> p.dataReceived(data)
        >>> p.service['MB'].call_count == 1 and p.service['PL'].call_count == 1 and p.service['VE'].call_count == 2 and p.service['CB'].call_count == 1
        True
        """
        self.buffer += data

        for x in range(50):
            if not self.parse_buffer():
                break
            else:
                for msg in self.messages:
                    self.parse_msg(msg)
                del self.messages[:]

    def connectionMade(self):
        peerHost, peerPort = self.transport.getPeer().host, self.transport.getPeer().port
        self.conn_identity = "{}:{}".format(peerHost, peerPort)

        # FIXME: (For AWS) This could be problematic for other users
        if config.dev.public_ip:
            if self.transport.getPeer().host == config.dev.public_ip:
                self.transport.loseConnection()
                return

        if len(self.factory.peer_connections) >= config.user.max_peers_limit:
            # FIXME: Should we stop listening to avoid unnecessary load due to many connections?
            logger.info('Peer limit hit ')
            logger.info('# of Connected peers %s', len(self.factory.peer_connections))
            logger.info('Peer Limit %s', config.user.max_peers_limit)
            logger.info('Disconnecting client %s', self.conn_identity)
            self.transport.loseConnection()
            return

        self.factory.connections += 1
        self.factory.peer_connections.append(self)
        peer_list = self.factory.node.peer_addresses

        if self.transport.getPeer().host == self.transport.getHost().host:
            if self.transport.getPeer().host in peer_list:
                logger.info('Self in peer_list, removing..')
                peer_list.remove(self.transport.getPeer().host)
                # FIXME
                self.factory.node.update_peer_addresses(peer_list)

            self.transport.loseConnection()
            return

        if self.transport.getPeer().host not in peer_list:
            logger.info('Adding to peer_list')
            peer_list.append(self.transport.getPeer().host)
            # FIXME
            self.factory.node.update_peer_addresses(peer_list)

        logger.info('>>> new peer connection : %s:%s ',
                    self.transport.getPeer().host,
                    str(self.transport.getPeer().port))

        self.get_m_blockheight_from_connection()
        self.get_peers()
        self.get_version()
        self.disconnect_callLater = reactor.callLater(config.user.ping_timeout, self.transport.loseConnection)
        self.ping_callLater = reactor.callLater(1, self.PING)

    # here goes the code for handshake..using functions within the p2pprotocol class
    # should ask for latest block/block number.

    def connectionLost(self, reason=connectionDone):
        logger.info('%s disconnected. remainder connected: %s',
                    self.transport.getPeer().host,
                    str(self.factory.connections))  # , reason
        try:
            self.factory.peer_connections.remove(self)
            self.factory.connections -= 1

            if self.conn_identity in self.factory.target_peers:
                del self.factory.target_peers[self.conn_identity]
            host_port = self.transport.getPeer().host + ':' + str(self.transport.getPeer().port)
            if host_port in self.factory.peers_blockheight:
                del self.factory.peers_blockheight[host_port]

            if self.factory.connections == 0:
                reactor.callLater(60, self.factory.connect_peers)
        except Exception:
            pass

    def recv_tx(self, json_tx_obj):
        try:
            tx = Transaction.from_json(json_tx_obj)
        except Exception as e:
            logger.info('tx rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(tx.get_message_hash(), self):
            return

        if tx.txhash in self.factory.chain.prev_txpool or tx.txhash in self.factory.chain.pending_tx_pool_hash:
            return

        del self.factory.chain.prev_txpool[0]
        self.factory.chain.prev_txpool.append(tx.txhash)

        for t in self.factory.chain.transaction_pool:  # duplicate tx already received, would mess up nonce..
            if tx.txhash == t.txhash:
                return

        self.factory.chain.update_pending_tx_pool(tx, self)

        self.factory.master_mr.register(tx.get_message_hash(), json_tx_obj, 'TX')
        self.factory.broadcast(tx.get_message_hash(), 'TX')

        if not self.factory.txn_processor_running:
            txn_processor = TxnProcessor(block_chain_buffer=self.factory.chain.block_chain_buffer,
                                         pending_tx_pool=self.factory.chain.pending_tx_pool,
                                         transaction_pool=self.factory.chain.transaction_pool,
                                         txhash_timestamp=self.factory.chain.txhash_timestamp)

            task_defer = TxnProcessor.create_cooperate(txn_processor).whenDone()
            task_defer.addCallback(self.factory.reset_processor_flag) \
                .addErrback(self.factory.reset_processor_flag_with_err)
            self.factory.txn_processor_running = True
        return
