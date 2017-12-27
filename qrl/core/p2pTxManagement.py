from queue import PriorityQueue
from pyqrllib.pyqrllib import bin2hstr
from twisted.internet import reactor

from qrl.core.ESyncState import ESyncState
from qrl.core.Transaction import Transaction
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage

from qrl.core.messagereceipt import MessageReceipt

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.p2pObserver import P2PBaseObserver
from qrl.generated import qrllegacy_pb2


class P2PTxManagement(P2PBaseObserver):
    def __init__(self):
        super().__init__()

    def new_channel(self, channel):
        channel.register(qrllegacy_pb2.LegacyMessage.MR, self.handle_message_received)
        channel.register(qrllegacy_pb2.LegacyMessage.SFM, self.handle_full_message_request)

        channel.register(qrllegacy_pb2.LegacyMessage.BK, self.handle_block)
        channel.register(qrllegacy_pb2.LegacyMessage.TX, self.handle_tx)
        channel.register(qrllegacy_pb2.LegacyMessage.ST, self.handle_stake)
        channel.register(qrllegacy_pb2.LegacyMessage.DST, self.handle_destake)
        channel.register(qrllegacy_pb2.LegacyMessage.DT, self.handle_duplicate)
        channel.register(qrllegacy_pb2.LegacyMessage.VT, self.handle_vote)
        channel.register(qrllegacy_pb2.LegacyMessage.LT, self.handle_lattice)
        channel.register(qrllegacy_pb2.LegacyMessage.EPH, self.handle_ephemeral)

    def handle_message_received(self, source, message: qrllegacy_pb2.LegacyMessage):
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

        # FIXME: Separate into respective message handlers

        if mr_data.type not in MessageReceipt.allowed_types:
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.TX and source.factory.sync_state.state != ESyncState.synced:
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.TX:
            if len(source.factory._buffered_chain.tx_pool.pending_tx_pool) >= config.dev.transaction_pool_size:
                logger.warning('TX pool size full, incoming tx dropped. mr hash: %s', bin2hstr(msg_hash))
                return

        if mr_data.type in [qrllegacy_pb2.LegacyMessage.ST, qrllegacy_pb2.LegacyMessage.VT]:
            if source.factory.chain_height > 1 and source.factory.sync_state.state != ESyncState.synced:
                return

        if source.factory.master_mr.contains(msg_hash, mr_data.type):
            return

        source.factory.master_mr.add_peer(msg_hash, mr_data.type, source, mr_data)

        if source.factory.master_mr.is_callLater_active(msg_hash):  # Ignore if already requested
            return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.BK:
            # FIXME: Move to buffered chain
            if not source.factory._buffered_chain.verify_BK_hash(mr_data, source.connection_id):
                if source.factory._buffered_chain.is_duplicate_block(block_idx=mr_data.block_number,
                                                                     prev_headerhash=mr_data.prev_headerhash,
                                                                     stake_selector=mr_data.stake_selector):
                    source.factory.request_full_message(mr_data)
                return

            blocknumber = mr_data.block_number
            target_blocknumber = source.factory._buffered_chain.bkmr_tracking_blocknumber(source.factory._ntp)
            if target_blocknumber != source.factory.bkmr_blocknumber:
                source.factory.bkmr_blocknumber = target_blocknumber
                del source.factory.bkmr_priorityq
                source.factory.bkmr_priorityq = PriorityQueue()

            if blocknumber != target_blocknumber or blocknumber == 1:
                source.factory.request_full_message(mr_data)
                return

            score = source.factory._buffered_chain.score_BK_hash(mr_data)
            source.factory.bkmr_priorityq.put((score, msg_hash))

            if not source.factory.bkmr_processor.active():
                source.factory.bkmr_processor = reactor.callLater(1, source.factory.select_best_bkmr)

            return

        source.factory.request_full_message(mr_data)

    def handle_full_message_request(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Send Full Message
        This function serves the request made for the full message.
        :return:
        """
        msg = source.factory.master_mr.get(message.mrData.type, message.mrData.hash)
        if msg is not None:
            source.send(msg)

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def process(self, factory, tx):
        if not tx.validate():
            return False

        buffered_chain = factory._buffered_chain

        tx_state = buffered_chain.get_stxn_state(blocknumber=buffered_chain.height,
                                                 addr=tx.txfrom)

        is_valid_state = tx.validate_extended(tx_state=tx_state,
                                              transaction_pool=buffered_chain.tx_pool.transaction_pool)
        return is_valid_state

    def handle_tx(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Transaction
        Executed whenever a new TX type message is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.TX)
        tx = Transaction(message.txData)

        # NOTE: Connects to MR
        if not source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            return

        self.process(source.factory, tx)

    def handle_vote(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Vote Transaction
        This function processes whenever a Transaction having
        subtype VOTE is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.VT)
        try:
            vote = Transaction.from_pbdata(message.vtData)
        except Exception as e:
            logger.error('Vote Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(vote.get_message_hash(), source):
            return

    def handle_message_transaction(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Message Transaction
        This function processes whenever a Transaction having
        subtype MESSAGE is received.
        :return:
        """
        source._validate_message(message, qrllegacy_pb2.LegacyMessage.MT)
        try:
            tx = Transaction.from_pbdata(message.mtData)
        except Exception as e:
            logger.error('Message Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            return

        if tx.txhash in source.factory.buffered_chain.tx_pool.pending_tx_pool_hash:
            return

        self.process(source.factory, tx)

    def handle_token_transaction(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Token Transaction
        This function processes whenever a Transaction having
        subtype TOKEN is received.
        :return:
        """
        source._validate_message(message, qrllegacy_pb2.LegacyMessage.TT)
        try:
            tx = Transaction.from_pbdata(message.mtData)
        except Exception as e:
            logger.error('Transfer Token Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            return

        if tx.txhash in source.factory.buffered_chain.tx_pool.pending_tx_pool_hash:
            return

        self.process(source.factory, tx)

    def handle_transfer_token_transaction(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Message Transaction
        This function processes whenever a Transaction having
        subtype MESSAGE is received.
        :return:
        """
        source._validate_message(message, qrllegacy_pb2.LegacyMessage.TK)
        try:
            tx = Transaction.from_pbdata(message.mtData)
        except Exception as e:
            logger.error('Token Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            return

        if tx.txhash in source.factory.buffered_chain.tx_pool.pending_tx_pool_hash:
            return

        self.process(source.factory, tx)

    def handle_stake(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Stake Transaction
        This function processes whenever a Transaction having
        subtype ST is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.ST)
        try:
            st = Transaction.from_pbdata(message.stData)
        except Exception as e:
            logger.error('st rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(st.get_message_hash(), source):
            return

        if len(source.factory._buffered_chain._chain.blockchain) == 1 and \
                st.activation_blocknumber > source.factory.chain_height + config.dev.blocks_per_epoch:
            return

        height = source.factory.chain_height + 1
        stake_validators_tracker = source.factory._buffered_chain.get_stake_validators_tracker(height)

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

        for t in source.factory._buffered_chain.tx_pool.transaction_pool:
            if st.get_message_hash() == t.get_message_hash():
                return

        tx_state = source.factory._buffered_chain.get_stxn_state(
            blocknumber=source.factory.chain_height + 1,
            addr=st.txfrom)
        if st.validate() and st.validate_extended(tx_state=tx_state):
            source.factory._buffered_chain.tx_pool.add_tx_to_pool(st)
        else:
            logger.warning('>>>ST %s invalid state validation failed..', bin2hstr(tuple(st.hash)))
            return

        source.factory.register_and_broadcast(qrllegacy_pb2.LegacyMessage.ST, st.get_message_hash(), st.pbdata)

    def handle_destake(self, source, message: qrllegacy_pb2.LegacyMessage):
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
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(destake_txn.get_message_hash(), source):
            return

        for t in source.factory._buffered_chain.tx_pool.transaction_pool:
            if destake_txn.get_message_hash() == t.get_message_hash():
                return

        txfrom = destake_txn.txfrom
        height = source.factory.chain_height + 1
        stake_validators_tracker = source.factory._buffered_chain.get_stake_validators_tracker(height)

        if not (
                txfrom in stake_validators_tracker.sv_dict or txfrom in stake_validators_tracker.future_stake_addresses):
            logger.debug('P2P Dropping destake txn as %s not found in stake validator list', txfrom)
            return

        tx_state = source.factory._buffered_chain.get_stxn_state(
            blocknumber=height,
            addr=txfrom)
        if destake_txn.validate() and destake_txn.validate_extended(tx_state=tx_state):
            source.factory._buffered_chain.tx_pool.add_tx_to_pool(destake_txn)
        else:
            logger.debug('>>>Destake %s invalid state validation failed..', txfrom)
            return

        source.factory.register_and_broadcast('DST', destake_txn.get_message_hash(), destake_txn.to_json())

    def handle_duplicate(self, source, message: qrllegacy_pb2.LegacyMessage):
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
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(duplicate_txn.get_message_hash(), source):
            return

        if duplicate_txn.get_message_hash() in source.factory._buffered_chain.tx_pool.duplicate_tx_pool:
            return

        # TODO: State validate for duplicate_txn is pending
        if duplicate_txn.validate():
            source.factory._buffered_chain.tx_pool.add_tx_to_duplicate_pool(duplicate_txn)
        else:
            logger.debug('>>>Invalid DT txn %s', bin2hstr(duplicate_txn.get_message_hash()))
            return

        source.factory.register_and_broadcast('DT', duplicate_txn.get_message_hash(), duplicate_txn.to_json())

    def handle_block(self, source, message: qrllegacy_pb2.LegacyMessage):  # block received
        """
        Block
        This function processes any new block received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.BK)
        try:
            block = Block(message.block)
        except Exception as e:
            logger.error('block rejected - unable to decode serialised data %s', source.peer_ip)
            logger.exception(e)
            return

        logger.info('>>>Received block from %s %s %s',
                    source.connection_id,
                    block.block_number,
                    block.stake_selector)

        if not source.factory.master_mr.isRequested(block.headerhash, source, block):
            return

        if source.factory._buffered_chain.is_duplicate_block(block_idx=block.block_number,
                                                             prev_headerhash=block.prev_headerhash,
                                                             stake_selector=block.stake_selector):
            logger.info('Found duplicate block #%s by %s',
                        block.block_number,
                        block.stake_selector)

        source.factory.pos.pre_block_logic(block)  # FIXME: Ignores return value
        source.factory.master_mr.register(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, message)

    def handle_ephemeral(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Ephemeral Message
        :param message:
        :return:
        """
        try:
            encrypted_ephemeral = EncryptedEphemeralMessage.from_json(message)
        except Exception as e:
            logger.error('ephemeral_message rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(encrypted_ephemeral.get_message_hash(), self):
            return

        if not encrypted_ephemeral.validate():
            return

        source.factory.buffered_chain.add_ephemeral_message(encrypted_ephemeral)

    def handle_lattice(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Lattice Public Key Transaction
        :param message:
        :return:
        """

        try:
            tx = Transaction.from_json(message)
        except Exception as e:
            logger.error('lattice_public_key rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if not source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            return

        if not tx.validate():
            logger.warning('>>>Lattice Public Key %s invalid state validation failed..', tx.hash)
            return

        if tx.txhash in source.factory.buffered_chain.tx_pool.pending_tx_pool_hash:
            return

        self.process(source.factory, tx)
