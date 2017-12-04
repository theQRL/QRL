# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import struct
import time
from queue import PriorityQueue

from pyqrllib.pyqrllib import bin2hstr, hstr2bin
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone

from qrl.core import config, logger
from qrl.core.Block import Block
from qrl.core.ESyncState import ESyncState
from qrl.core.Transaction import Transaction
from qrl.core.messagereceipt import MessageReceipt
from qrl.generated import qrllegacy_pb2


# SubService Network (Discovery/Health)
# SubService Synchronization (Block Chain/ForkHealing/etc)
# SubService POS Controller
# SubService TX Propagation

# NOTE: There is a consistency problem in the message objects.
# NOTE: There are three cases, 1) send request 2) recv request 3) recv respose (implicit )

class P2PProtocol(Protocol):
    def __init__(self):
        self._services = {
            ######################
            qrllegacy_pb2.LegacyMessage.VE: self.handle_version,
            qrllegacy_pb2.LegacyMessage.PL: self.handle_peer_list,
            qrllegacy_pb2.LegacyMessage.PONG: self.handle_pong,

            ######################
            qrllegacy_pb2.LegacyMessage.MR: self.MR,        # RECV+Filters      It will send a RequestFullMessage
            qrllegacy_pb2.LegacyMessage.SFM: self.SFM,      # RECV=>SEND        Send Full Message

            qrllegacy_pb2.LegacyMessage.BK: self.handle_bk,        # RECV      Block
            qrllegacy_pb2.LegacyMessage.FB: self.handle_fb,        # Fetch request for block
            qrllegacy_pb2.LegacyMessage.PB: self.handle_push_block,        # Push Block

            ############################
            qrllegacy_pb2.LegacyMessage.ST: self.handle_st,        # RECV/BCAST        Stake Transaction
            qrllegacy_pb2.LegacyMessage.DST: self.DST,      # Destake Transaction
            qrllegacy_pb2.LegacyMessage.DT: self.DT,        # Duplicate Transaction

            ############################
            qrllegacy_pb2.LegacyMessage.TX: self.handle_tx, # RECV Transaction
            qrllegacy_pb2.LegacyMessage.VT: self.handle_vt,        # Vote Txn
            qrllegacy_pb2.LegacyMessage.LT: self.LT,        # Lattice Public Key Transaction

            qrllegacy_pb2.LegacyMessage.EPH: self.EPH,      # Ephemeral Transaction

            qrllegacy_pb2.LegacyMessage.SYNC: self.handle_sync,  # Add into synced list, if the node replies
        }
        self._buffer = b''
        self._last_requested_blocknum = None
        self._conn_identity = None
        self._prev_txpool_hashes = [None] * 1000
        self._disconnect_callLater = None
        self._ping_callLater = None

    @property
    def host_ip(self):
        return self.transport.getPeer().host

    def _validate_message(self, message: qrllegacy_pb2.LegacyMessage, expected_func):
        if message.func_name != expected_func:
            raise ValueError("Invalid func_name")

    def MR(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Message Receipt
        This function accepts message receipt from peer,
        checks if the message hash already been received or not.
        In case its a already received message, it is ignored.
        Otherwise the request is made to get the full message.
        :return:
        """
        mr_data = message.mrData
        msg_hash = mr_data.hash

        if mr_data.type not in MessageReceipt.allowed_types:
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.TX and self.factory.sync_state.state != ESyncState.synced:
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.TX:
            if len(self.factory.buffered_chain.tx_pool.pending_tx_pool) >= config.dev.transaction_pool_size:
                logger.warning('TX pool size full, incoming tx dropped. mr hash: %s', bin2hstr(msg_hash))
                return

        if mr_data.type in [qrllegacy_pb2.LegacyMessage.ST, qrllegacy_pb2.LegacyMessage.VT]:
            if self.factory.buffered_chain.height > 1 and self.factory.sync_state.state != ESyncState.synced:
                return

        if self.factory.master_mr.contains(msg_hash, mr_data.type):
            return

        self.factory.master_mr.add_peer(msg_hash, mr_data.type, self, mr_data)

        if self.factory.master_mr.is_callLater_active(msg_hash):  # Ignore if already requested
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.BK:
            block_chain_buffer = self.factory.buffered_chain

            if not block_chain_buffer.verify_BK_hash(mr_data, self._conn_identity):
                if block_chain_buffer.is_duplicate_block(block_idx=mr_data.block_number,
                                                         prev_headerhash=mr_data.prev_headerhash,
                                                         stake_selector=mr_data.stake_selector):
                    self.factory.RFM(mr_data)
                return

            blocknumber = mr_data.block_number
            target_blocknumber = block_chain_buffer.bkmr_tracking_blocknumber(self.factory.ntp)
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

    def SFM(self, message: qrllegacy_pb2.LegacyMessage):  # Send full message
        """
        Send Full Message
        This function serves the request made for the full message.
        :return:
        """
        mr_data = message.mrData
        msg_hash = mr_data.hash
        msg_type = mr_data.type

        if not self.factory.master_mr.contains(msg_hash, msg_type):
            return

        # Sending message from node, doesn't guarantee that peer has received it.
        # Thus requesting peer could re request it, may be ACK would be required
        msg = self.factory.master_mr.hash_msg[msg_hash].msg
        data = qrllegacy_pb2.LegacyMessage(**{'func_name': msg_type,
                                              self.factory.services_arg[msg_type]: msg})
        self.transport.write(self.wrap_message(data))

    def handle_tx(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Transaction
        Executed whenever a new TX type message is received.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.TX)
        tx = Transaction(message.txData)
        if not self.factory.master_mr.isRequested(tx.get_message_hash(), self):
            return

        if tx.txhash in self._prev_txpool_hashes or \
                tx.txhash in self.factory.buffered_chain.tx_pool.pending_tx_pool_hash:
            return

        del self._prev_txpool_hashes[0]
        self._prev_txpool_hashes.append(tx.txhash)

        self.factory.trigger_tx_processor(tx, message)

    def handle_vt(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Vote Transaction
        This function processes whenever a Transaction having
        subtype VOTE is received.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.VT)
        try:
            vote = Transaction.from_pbdata(message.vtData)
        except Exception as e:
            logger.error('Vote Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(vote.get_message_hash(), self):
            return

        if self.factory.buffered_chain.add_vote(vote):
            self.factory.register_and_broadcast(qrllegacy_pb2.LegacyMessage.VT, vote.get_message_hash(), vote.pbdata)

    def handle_st(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Stake Transaction
        This function processes whenever a Transaction having
        subtype ST is received.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.ST)
        try:
            st = Transaction.from_pbdata(message.stData)
        except Exception as e:
            logger.error('st rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(st.get_message_hash(), self):
            return

        if len(self.factory.buffered_chain._chain.blockchain) == 1 and \
                st.activation_blocknumber > self.factory.buffered_chain.height + config.dev.blocks_per_epoch:
            return

        height = self.factory.buffered_chain.height + 1
        stake_validators_tracker = self.factory.buffered_chain.get_stake_validators_tracker(height)

        if st.txfrom in stake_validators_tracker.future_stake_addresses:
            logger.debug('P2P dropping st as staker is already in future_stake_address %s', st.txfrom)
            return

        if st.txfrom in stake_validators_tracker.sv_dict:
            expiry = stake_validators_tracker.sv_dict[st.txfrom].activation_blocknumber + config.dev.blocks_per_epoch
            if st.activation_blocknumber < expiry:
                logger.debug('P2P dropping st txn as it is already active for the given range %s', st.txfrom)
                return

        if st.activation_blocknumber > height + config.dev.blocks_per_epoch:
            logger.debug('P2P dropping st as activation_blocknumber beyond limit')
            return False

        for t in self.factory.buffered_chain.tx_pool.transaction_pool:
            if st.get_message_hash() == t.get_message_hash():
                return

        tx_state = self.factory.buffered_chain.get_stxn_state(
            blocknumber=self.factory.buffered_chain.height + 1,
            addr=st.txfrom)
        if st.validate() and st.validate_extended(tx_state=tx_state):
            self.factory.buffered_chain.tx_pool.add_tx_to_pool(st)
        else:
            logger.warning('>>>ST %s invalid state validation failed..', bin2hstr(tuple(st.hash)))
            return

        self.factory.register_and_broadcast(qrllegacy_pb2.LegacyMessage.ST, st.get_message_hash(), st.pbdata)

    def DST(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Destake Transaction
        This function processes whenever a Transaction having
        subtype DESTAKE is received.
        :return:
        """
        try:
            destake_txn = Transaction.from_json(message)
        except Exception as e:
            logger.error('de stake rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(destake_txn.get_message_hash(), self):
            return

        for t in self.factory.buffered_chain.tx_pool.transaction_pool:
            if destake_txn.get_message_hash() == t.get_message_hash():
                return

        txfrom = destake_txn.txfrom
        height = self.factory.buffered_chain.height + 1
        stake_validators_tracker = self.factory.buffered_chain.get_stake_validators_tracker(height)

        if txfrom not in stake_validators_tracker.sv_dict and txfrom not in stake_validators_tracker.future_stake_addresses:
            logger.debug('P2P Dropping destake txn as %s not found in stake validator list', txfrom)
            return

        tx_state = self.factory.buffered_chain.get_stxn_state(
            blocknumber=height,
            addr=txfrom)
        if destake_txn.validate() and destake_txn.validate_extended(tx_state=tx_state):
            self.factory.buffered_chain.tx_pool.add_tx_to_pool(destake_txn)
        else:
            logger.debug('>>>Destake %s invalid state validation failed..', txfrom)
            return

        self.factory.register_and_broadcast('DST', destake_txn.get_message_hash(), destake_txn.to_json())

    def DT(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Duplicate Transaction
        This function processes whenever a Transaction having
        subtype DT is received.
        :return:
        """
        try:
            duplicate_txn = Transaction.from_json(message)
        except Exception as e:
            logger.error('DT rejected')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(duplicate_txn.get_message_hash(), self):
            return

        if duplicate_txn.get_message_hash() in self.factory.buffered_chain.tx_pool.duplicate_tx_pool:
            return

        # TODO: State validate for duplicate_txn is pending
        if duplicate_txn.validate():
            self.factory.buffered_chain.tx_pool.add_tx_to_duplicate_pool(duplicate_txn)
        else:
            logger.debug('>>>Invalid DT txn %s', bin2hstr(duplicate_txn.get_message_hash()))
            return

        self.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())

    def handle_bk(self, message: qrllegacy_pb2.LegacyMessage):  # block received
        """
        Block
        This function processes any new block received.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.BK)
        try:
            block = Block(message.block)
        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.transport.getPeer().host)
            logger.exception(e)
            return

        logger.info('>>>Received block from %s %s %s',
                    self._conn_identity,
                    block.block_number,
                    block.stake_selector)

        if not self.factory.master_mr.isRequested(block.headerhash, self, block):
            return

        block_chain_buffer = self.factory.buffered_chain

        if block_chain_buffer.is_duplicate_block(block_idx=block.block_number,
                                                 prev_headerhash=block.prev_headerhash,
                                                 stake_selector=block.stake_selector):
            logger.info('Found duplicate block #%s by %s',
                        block.block_number,
                        block.stake_selector)
            # FIXME : Commented for now, need to re-enable once DT txn has been fixed
            '''
            # coinbase_txn = CoinBase.from_pbdata(block.transactions[0])
            #
            # sv_dict = self.factory.buffered_chain.stake_list_get(block.block_number)
            if coinbase_txn.validate_extended(sv_dict=sv_dict, blockheader=block.blockheader):
                self.factory.master_mr.register_duplicate(block.headerhash)
                block2 = block_chain_buffer.get_block_n(block.blocknumber)

                duplicate_txn = DuplicateTransaction().create(block1=block, block2=block2)
                if duplicate_txn.validate():
                    self.factory.buffered_chain._chain.add_tx_to_duplicate_pool(duplicate_txn)
                    self.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())
            '''
        self.factory.pos.pre_block_logic(block)  # FIXME: Ignores return value
        self.factory.master_mr.register(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, message)

    def handle_push_block(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Push Block
        This function processes requested blocks received while syncing.
        Block received under this function are directly added to the main
        chain i.e. chain.blockchain
        It is expected to receive only one block for a given blocknumber.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.PB)
        if message.pbData is None:
            return

        self.factory.pos.last_pb_time = time.time()
        try:
            block = Block(message.pbData.block)
            logger.info('>>> Received Block #%d', block.block_number)

            if not self.factory.buffered_chain.check_expected_headerhash(block.block_number,
                                                                         block.headerhash):
                logger.warning('Block #%s downloaded from peer doesnt match with expected headerhash',
                               message.pbData.block.block_number)
                return

            if block.block_number != self._last_requested_blocknum:
                logger.warning('Did not match %s %s', self._last_requested_blocknum, self._conn_identity)
                return

            self._last_requested_blocknum = None

            # FIXME: This check should not be necessary
            if block.block_number > self.factory.buffered_chain.height:
                if not self.factory.buffered_chain.add_block(block):
                    logger.warning('PB failed to add block to mainchain')
                    self.factory.buffered_chain.remove_last_buffer_block()
                    return

            try:
                reactor.download_monitor.cancel()
            except Exception as e:
                logger.warning("PB: %s", e)

            self.factory.pos.randomize_block_fetch()        # NOTE: Get next block

        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.transport.getPeer().host)
            logger.exception(e)

    def handle_fb(self, message: qrllegacy_pb2.LegacyMessage):  # Fetch Request for block
        """
        Fetch Block
        Sends the request for the block.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.FB)

        idx = message.fbData.index
        logger.info(' Request for %s by %s', idx, self._conn_identity)
        if 0 < idx <= self.factory.buffered_chain.height:
            blocknumber = idx

            block = self.factory.buffered_chain.get_block(blocknumber)
            # FIXME: Breaking encapsulation
            pb_data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PB,
                                                  pbData=qrllegacy_pb2.PBData(block=block.pbdata))
            self.transport.write(self.wrap_message(pb_data))

    def send_pong(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PONG)
        self.transport.write(self.wrap_message(msg))
        logger.debug('Sending PING to %s', self._conn_identity)

    def handle_pong(self, message: qrllegacy_pb2.LegacyMessage):
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.PONG)

        self._disconnect_callLater.reset(config.user.ping_timeout)
        if self._ping_callLater.active():
            self._ping_callLater.cancel()

        self._ping_callLater = reactor.callLater(config.user.ping_frequency, self.send_pong)
        logger.debug('Received PONG from %s', self._conn_identity)

    def send_peer_list(self):
        """
        Get Peers
        Sends the peers list.
        :return:
        """
        logger.info('<<<Sending connected peers to %s', self.transport.getPeer().host)
        peer_ips = self.factory.get_connected_peer_ips()

        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                          plData=qrllegacy_pb2.PLData(peer_ips=peer_ips))

        self.transport.write(self.wrap_message(msg))

    def handle_peer_list(self, message: qrllegacy_pb2.LegacyMessage):
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.PL)

        if not config.user.enable_peer_discovery:
            return

        if message.peer_ips is None:
            return

        new_ips = set(ip for ip in message.peer_ips)
        new_ips.discard(self.transport.getHost().host)              # Remove local address
        self.factory.qrl_node.update_peer_addresses(new_ips)

        logger.info('%s peers data received: %s', self.transport.getPeer().host, new_ips)

    def send_version(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE)
        self.transport.write(self.wrap_message(msg))

    def handle_version(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Version
        If data is None then sends the version & genesis_prev_headerhash.
        Otherwise, process the content of data and incase of non matching,
        genesis_prev_headerhash, it disconnects the odd peer.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.VE)

        if message.veData is None:
            msg = qrllegacy_pb2.LegacyMessage(
                func_name=qrllegacy_pb2.LegacyMessage.VE,
                veData=qrllegacy_pb2.VEData(version=config.dev.version,
                                            genesis_prev_hash=bytes(config.dev.genesis_prev_headerhash.encode())))

            self.transport.write(self.wrap_message(msg))
            return

        logger.info('%s version: %s | genesis prev_headerhash %s',
                    self.transport.getPeer().host,
                    message.veData.version,
                    message.veData.genesis_prev_hash)

        if message.veData.genesis_prev_hash != config.dev.genesis_prev_headerhash:
            logger.warning('%s genesis_prev_headerhash mismatch', self._conn_identity)
            logger.warning('Expected: %s', config.dev.genesis_prev_headerhash)
            logger.warning('Found: %s', message.veData.genesis_prev_headerhash)
            self.transport.loseConnection()

    def EPH(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Ephemeral Transaction
        :param message:
        :return:
        """
        pass

    def LT(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Lattice Public Key Transaction
        :param message:
        :return:
        """

        try:
            lattice_public_key_txn = Transaction.from_json(message)
        except Exception as e:
            logger.error('lattice_public_key rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(lattice_public_key_txn.get_message_hash(), self):
            return

        if lattice_public_key_txn.validate():
            self.factory.buffered_chain.add_lattice_public_key(lattice_public_key_txn)
        else:
            logger.warning('>>>Lattice Public Key %s invalid state validation failed..', lattice_public_key_txn.hash)
            return

        # TODO: This need to be moved to add_block before next hard fork
        self.factory.buffered_chain.add_lattice_public_key(lattice_public_key_txn)

        self.factory.register_and_broadcast('LT',
                                            lattice_public_key_txn.get_message_hash(),
                                            lattice_public_key_txn.to_json())

    def send_sync(self):
        data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                           syncData=qrllegacy_pb2.SYNCData(state=''))
        self.transport.write(self.wrap_message(data))

    def handle_sync(self, message: qrllegacy_pb2.LegacyMessage):
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.SYNC)

        if message.syncData.state == 'Synced':
            self.factory.set_peer_synced(self, True)
        elif message.syncData.state == '':
            if self.factory.pos.sync_state.state == ESyncState.synced:
                data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                                   syncData=qrllegacy_pb2.SYNCData(state='Synced'))
                self.transport.write(self.wrap_message(data))
                self.factory.set_peer_synced(self, False)

    def fetch_block_n(self, n):
        """
        Fetch Block n
        Sends request for the block number n.
        :return:
        """
        self._last_requested_blocknum = n
        logger.info('<<<Fetching block: %s from %s', n, self._conn_identity)
        fb_data = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.FB,
                                              fbData=qrllegacy_pb2.FBData(index=n))
        self.transport.write(self.wrap_message(fb_data))

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Low-level serialization/connections/etc
    # FIXME: This is a temporary refactoring, it will be completely replaced before release
    def _dispatch_messages(self, message: qrllegacy_pb2.LegacyMessage):
        func = self._services.get(message.func_name)
        if func:
            try:
                # FIXME: use WhichOneof to discover payloads
                func(message)
            except Exception as e:
                logger.debug("executing [%s] by %s", message.func_name, self._conn_identity)
                logger.exception(e)

    @staticmethod
    def wrap_message(protobuf_obj) -> bytes:
        """
        Receives a protobuf object and encodes it as (length)(data)
        :return: the encoded message
        :rtype: bytes
        >>> veData = qrllegacy_pb2.VEData(version="version", genesis_prev_hash=b'genesis_hash')
        >>> msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE, veData=veData)
        >>> bin2hstr(P2PProtocol.wrap_message(msg))
        '000000191a170a0776657273696f6e120c67656e657369735f68617368'
        """
        # FIXME: This is not the final implementation, it is just a workaround for refactoring
        # FIXME: struct.pack may result in endianness problems
        # NOTE: This temporary approach does not allow for alignment. Once the stream is off, it will need to clear
        data = protobuf_obj.SerializeToString()
        str_data_len = struct.pack('>L', len(data))
        return str_data_len + data

    def _parse_buffer(self):
        # FIXME: This parsing/wire protocol needs to be replaced
        """
        >>> p=P2PProtocol()
        >>> p._buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'+ \
                                       '000000191a170a0776657273696f6e120c67656e657369735f68617368'))
        >>> messages = p._parse_buffer()
        >>> len(list(messages))
        2
        """
        while self._buffer:
            # FIXME: This is not the final implementation, it is just a minimal implementation for refactoring
            if len(self._buffer) < 4:
                # Buffer is still incomplete as it doesn't have message size
                return

            chunk_size_raw = self._buffer[:4]
            chunk_size = struct.unpack('>L', chunk_size_raw)[0]  # is m length encoded correctly?

            # FIXME: There is no limitation on the buffer size or timeout
            if len(self._buffer) < chunk_size:
                # Buffer is still incomplete as it doesn't have message
                return

            try:
                message_raw = self._buffer[4:4 + chunk_size]
                message = qrllegacy_pb2.LegacyMessage()
                message.ParseFromString(message_raw)
                yield message
            except Exception as e:
                logger.warning("Problem parsing message. Skipping")
            finally:
                self._buffer = self._buffer[4 + chunk_size:]

    def dataReceived(self, data: bytes) -> None:
        self._buffer += data
        for msg in self._parse_buffer():
            self._dispatch_messages(msg)

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def connectionMade(self):
        self._conn_identity = "{}:{}".format(self.transport.getPeer().host,
                                             self.transport.getPeer().port)

        if self.factory.add_connection(self):
            self.send_peer_list()
            self.send_version()

        self._ping_callLater = reactor.callLater(1, self.send_pong)
        self._disconnect_callLater = reactor.callLater(config.user.ping_timeout,
                                                       self.transport.loseConnection)

    def connectionLost(self, reason=connectionDone):
        logger.info('%s disconnected. remainder connected: %s',
                    self.transport.getPeer().host,
                    str(self.factory.connections))  # , reason

        self.factory.remove_connection(self)
