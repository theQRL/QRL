from queue import PriorityQueue

from pyqrllib.pyqrllib import bin2hstr
from twisted.internet import reactor

from qrl.core import config, logger
from qrl.core.Block import Block
from qrl.core.ESyncState import ESyncState
from qrl.core.Transaction import Transaction
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.p2pprotocol import P2PProtocol
from qrl.generated import qrllegacy_pb2


# SubService Network (Discovery/Health)
# SubService Synchronization (Block Chain/ForkHealing/etc)
# SubService POS Controller
# SubService TX Propagation

# NOTE: There is a consistency problem in the message objects.
# NOTE: There are three cases, 1) send request 2) recv request 3) recv respose (implicit )

# class P2PObservable(object):
#     def __init__(self, source):
#         # FIXME: Add mutexes
#         self.source = source
#         self._observers = dict()
#
#     def register(self, message_type, func: Callable):
#         # FIXME: Add mutexes
#         self._observers.setdefault(message_type, []).append(func)
#
#     def _notify(self, message: qrllegacy_pb2.LegacyMessage):
#         # FIXME: Add mutexes
#         observers = self._observers.get(message.msg_type, [])
#         for o in observers:
#             o(self, self.source, message)
#
#
# class P2PObserver(object):
#     def __init__(self, message_source: P2PObservable):
#         self.message_source = message_source
#
#
# class P2PPeerObserver(P2PObserver):
#     def __init__(self):
#         pass

class P2PHandler(P2PProtocol):
    def __init__(self):
        super().__init__()
        self._services = {
            # NODE STATE
            qrllegacy_pb2.LegacyMessage.VE: self.handle_version,
            qrllegacy_pb2.LegacyMessage.PL: self.handle_peer_list,
            qrllegacy_pb2.LegacyMessage.PONG: self.handle_pong,
            qrllegacy_pb2.LegacyMessage.SYNC: self.handle_sync,

            # SYNCHRONIZATION
            qrllegacy_pb2.LegacyMessage.FB: self.handle_fetch_block,
            qrllegacy_pb2.LegacyMessage.PB: self.handle_push_block,

            # CACHING
            qrllegacy_pb2.LegacyMessage.MR: self.handle_message_received,
            qrllegacy_pb2.LegacyMessage.SFM: self.handle_full_message_request,

            # Linked to MR...
            qrllegacy_pb2.LegacyMessage.TX: self.handle_tx,
            qrllegacy_pb2.LegacyMessage.ST: self.handle_stake,
            qrllegacy_pb2.LegacyMessage.DST: self.handle_destake,
            qrllegacy_pb2.LegacyMessage.DT: self.handle_duplicate,
            qrllegacy_pb2.LegacyMessage.VT: self.handle_vote,
            qrllegacy_pb2.LegacyMessage.LT: self.handle_lattice,
            qrllegacy_pb2.LegacyMessage.EPH: self.handle_ephemeral,
            qrllegacy_pb2.LegacyMessage.BK: self.handle_block,
        }

        self._last_requested_blocknum = None

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def send_version(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE)
        self.send(msg)

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

            self.send(msg)
            return

        logger.info('%s version: %s | genesis prev_headerhash %s',
                    self.peer_ip,
                    message.veData.version,
                    message.veData.genesis_prev_hash)

        if message.veData.genesis_prev_hash != config.dev.genesis_prev_headerhash:
            logger.warning('%s genesis_prev_headerhash mismatch', self._conn_identity)
            logger.warning('Expected: %s', config.dev.genesis_prev_headerhash)
            logger.warning('Found: %s', message.veData.genesis_prev_hash)
            self.loseConnection()

    def send_peer_list(self):
        """
        Get Peers
        Sends the peers list.
        :return:
        """
        logger.info('<<<Sending connected peers to %s', self.peer_ip)
        peer_ips = self.factory.get_connected_peer_ips()

        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                          plData=qrllegacy_pb2.PLData(peer_ips=peer_ips))

        self.send(msg)

    def handle_peer_list(self, message: qrllegacy_pb2.LegacyMessage):
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.PL)

        if not config.user.enable_peer_discovery:
            return

        if message.plData is None:
            return

        if message.plData.peer_ips is None:
            return

        new_ips = set(ip for ip in message.plData.peer_ips)
        new_ips.discard(self.host_ip)  # Remove local address
        self.factory.update_peer_addresses(new_ips)

        logger.info('%s peers data received: %s', self.peer_ip, new_ips)

    def send_pong(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PONG)
        self.send(msg)
        logger.debug('Sending PING to %s', self._conn_identity)

    def handle_pong(self, message: qrllegacy_pb2.LegacyMessage):
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.PONG)

        self._disconnect_callLater.reset(config.user.ping_timeout)
        if self._ping_callLater.active():
            self._ping_callLater.cancel()

        self._ping_callLater = reactor.callLater(config.user.ping_frequency, self.send_pong)
        logger.debug('Received PONG from %s', self._conn_identity)

    def send_sync(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                          syncData=qrllegacy_pb2.SYNCData(state=''))
        self.send(msg)

    def handle_sync(self, message: qrllegacy_pb2.LegacyMessage):
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.SYNC)

        if message.syncData.state == 'Synced':
            self.factory.set_peer_synced(self, True)
        elif message.syncData.state == '':
            if self.factory.synced:
                msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                                  syncData=qrllegacy_pb2.SYNCData(state='Synced'))
                self.send(msg)
                self.factory.set_peer_synced(self, False)

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def send_fetch_block(self, block_idx):
        """
        Fetch Block n
        Sends request for the block number n.
        :return:
        """
        logger.info('<<<Fetching block: %s from %s', block_idx, self._conn_identity)
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.FB,
                                          fbData=qrllegacy_pb2.FBData(index=block_idx))
        self.send(msg)

    def handle_fetch_block(self, message: qrllegacy_pb2.LegacyMessage):  # Fetch Request for block
        """
        Fetch Block
        Sends the request for the block.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.FB)

        block_number = message.fbData.index

        logger.info(' Request for %s by %s', block_number, self._conn_identity)
        if 0 < block_number <= self.factory.chain_height:
            block = self.factory.get_block(block_number)
            msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PB,
                                              pbData=qrllegacy_pb2.PBData(block=block.pbdata))
            self.send(msg)

    def handle_push_block(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Push Block
        This function processes requested blocks received while syncing.
        Block received under this function are directly added to the main
        chain i.e. chain.blockchain
        It is expected to receive only one block for a given blocknumber.
        :return:
        """
        # FIXME: Later rename
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.PB)
        if message.pbData is None:
            return

        try:
            block = Block(message.pbData.block)
            self.factory.block_received(block)

        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.peer_ip)
            logger.exception(e)

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    @staticmethod
    def _validate_message(message: qrllegacy_pb2.LegacyMessage, expected_func):
        if message.func_name != expected_func:
            raise ValueError("Invalid func_name")

    def handle_message_received(self, message: qrllegacy_pb2.LegacyMessage):
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
            if len(self.factory._buffered_chain.tx_pool.pending_tx_pool) >= config.dev.transaction_pool_size:
                logger.warning('TX pool size full, incoming tx dropped. mr hash: %s', bin2hstr(msg_hash))
                return

        if mr_data.type in [qrllegacy_pb2.LegacyMessage.ST, qrllegacy_pb2.LegacyMessage.VT]:
            if self.factory.chain_height > 1 and self.factory.sync_state.state != ESyncState.synced:
                return

        if self.factory.master_mr.contains(msg_hash, mr_data.type):
            return

        self.factory.master_mr.add_peer(msg_hash, mr_data.type, self, mr_data)

        if self.factory.master_mr.is_callLater_active(msg_hash):  # Ignore if already requested
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.BK:
            block_chain_buffer = self.factory._buffered_chain

            if not block_chain_buffer.verify_BK_hash(mr_data, self._conn_identity):
                if block_chain_buffer.is_duplicate_block(block_idx=mr_data.block_number,
                                                         prev_headerhash=mr_data.prev_headerhash,
                                                         stake_selector=mr_data.stake_selector):
                    self.factory.RFM(mr_data)
                return

            blocknumber = mr_data.block_number
            target_blocknumber = block_chain_buffer.bkmr_tracking_blocknumber(self.factory._ntp)
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

    def handle_full_message_request(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Send Full Message
        This function serves the request made for the full message.
        :return:
        """
        msg = self.factory.master_mr.get(message.mrData.type, message.mrData.hash)
        if msg is not None:
            self.send(msg)

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def handle_tx(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Transaction
        Executed whenever a new TX type message is received.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.TX)
        tx = Transaction(message.txData)

        # NOTE: Connects to MR
        if not self.factory.master_mr.isRequested(tx.get_message_hash(), self):
            return

        self.factory.trigger_tx_processor(tx, message)

    def handle_vote(self, message: qrllegacy_pb2.LegacyMessage):
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
            self.loseConnection()
            return

        if not self.factory.master_mr.isRequested(vote.get_message_hash(), self):
            return

        if self.factory._buffered_chain.add_vote(vote):
            self.factory.register_and_broadcast(qrllegacy_pb2.LegacyMessage.VT, vote.get_message_hash(), vote.pbdata)

    def handle_stake(self, message: qrllegacy_pb2.LegacyMessage):
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
            self.loseConnection()
            return

        if not self.factory.master_mr.isRequested(st.get_message_hash(), self):
            return

        if len(self.factory._buffered_chain._chain.blockchain) == 1 and \
                st.activation_blocknumber > self.factory.chain_height + config.dev.blocks_per_epoch:
            return

        height = self.factory.chain_height + 1
        stake_validators_tracker = self.factory._buffered_chain.get_stake_validators_tracker(height)

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

        for t in self.factory._buffered_chain.tx_pool.transaction_pool:
            if st.get_message_hash() == t.get_message_hash():
                return

        tx_state = self.factory._buffered_chain.get_stxn_state(
            blocknumber=self.factory.chain_height + 1,
            addr=st.txfrom)
        if st.validate() and st.validate_extended(tx_state=tx_state):
            self.factory._buffered_chain.tx_pool.add_tx_to_pool(st)
        else:
            logger.warning('>>>ST %s invalid state validation failed..', bin2hstr(tuple(st.hash)))
            return

        self.factory.register_and_broadcast(qrllegacy_pb2.LegacyMessage.ST, st.get_message_hash(), st.pbdata)

    def handle_destake(self, message: qrllegacy_pb2.LegacyMessage):
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
            self.loseConnection()
            return

        if not self.factory.master_mr.isRequested(destake_txn.get_message_hash(), self):
            return

        for t in self.factory._buffered_chain.tx_pool.transaction_pool:
            if destake_txn.get_message_hash() == t.get_message_hash():
                return

        txfrom = destake_txn.txfrom
        height = self.factory.chain_height + 1
        stake_validators_tracker = self.factory._buffered_chain.get_stake_validators_tracker(height)

        if not (
                txfrom in stake_validators_tracker.sv_dict or txfrom in stake_validators_tracker.future_stake_addresses):
            logger.debug('P2P Dropping destake txn as %s not found in stake validator list', txfrom)
            return

        tx_state = self.factory._buffered_chain.get_stxn_state(
            blocknumber=height,
            addr=txfrom)
        if destake_txn.validate() and destake_txn.validate_extended(tx_state=tx_state):
            self.factory._buffered_chain.tx_pool.add_tx_to_pool(destake_txn)
        else:
            logger.debug('>>>Destake %s invalid state validation failed..', txfrom)
            return

        self.factory.register_and_broadcast('DST', destake_txn.get_message_hash(), destake_txn.to_json())

    def handle_duplicate(self, message: qrllegacy_pb2.LegacyMessage):
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
            self.loseConnection()
            return

        if not self.factory.master_mr.isRequested(duplicate_txn.get_message_hash(), self):
            return

        if duplicate_txn.get_message_hash() in self.factory._buffered_chain.tx_pool.duplicate_tx_pool:
            return

        # TODO: State validate for duplicate_txn is pending
        if duplicate_txn.validate():
            self.factory._buffered_chain.tx_pool.add_tx_to_duplicate_pool(duplicate_txn)
        else:
            logger.debug('>>>Invalid DT txn %s', bin2hstr(duplicate_txn.get_message_hash()))
            return

        self.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())

    def handle_block(self, message: qrllegacy_pb2.LegacyMessage):  # block received
        """
        Block
        This function processes any new block received.
        :return:
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.BK)
        try:
            block = Block(message.block)
        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', self.peer_ip)
            logger.exception(e)
            return

        logger.info('>>>Received block from %s %s %s',
                    self._conn_identity,
                    block.block_number,
                    block.stake_selector)

        if not self.factory.master_mr.isRequested(block.headerhash, self, block):
            return

        block_chain_buffer = self.factory._buffered_chain

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
            # sv_dict = self.factory._buffered_chain.stake_list_get(block.block_number)
            if coinbase_txn.validate_extended(sv_dict=sv_dict, blockheader=block.blockheader):
                self.factory.master_mr.register_duplicate(block.headerhash)
                block2 = block_chain_buffer.get_block_n(block.blocknumber)

                duplicate_txn = DuplicateTransaction().create(block1=block, block2=block2)
                if duplicate_txn.validate():
                    self.factory._buffered_chain._chain.add_tx_to_duplicate_pool(duplicate_txn)
                    self.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())
            '''
        self.factory.pos.pre_block_logic(block)  # FIXME: Ignores return value
        self.factory.master_mr.register(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, message)

    def handle_ephemeral(self, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Ephemeral Transaction
        :param message:
        :return:
        """
        pass

    def handle_lattice(self, message: qrllegacy_pb2.LegacyMessage):
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
            self.loseConnection()
            return

        if not self.factory.master_mr.isRequested(lattice_public_key_txn.get_message_hash(), self):
            return

        if lattice_public_key_txn.validate():
            self.factory._buffered_chain.add_lattice_public_key(lattice_public_key_txn)
        else:
            logger.warning('>>>Lattice Public Key %s invalid state validation failed..', lattice_public_key_txn.hash)
            return

        # TODO: This need to be moved to add_block before next hard fork
        self.factory._buffered_chain.add_lattice_public_key(lattice_public_key_txn)

        self.factory.register_and_broadcast('LT',
                                            lattice_public_key_txn.get_message_hash(),
                                            lattice_public_key_txn.to_json())
