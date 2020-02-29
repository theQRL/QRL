from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.ESyncState import ESyncState
from qrl.core.txs.Transaction import Transaction
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.misc import logger, ntp
from qrl.core.p2p.p2pObserver import P2PBaseObserver
from qrl.generated import qrllegacy_pb2


class P2PTxManagement(P2PBaseObserver):
    def __init__(self):
        super().__init__()

    def new_channel(self, channel):
        channel.register(qrllegacy_pb2.LegacyMessage.MR, self.handle_message_received)
        channel.register(qrllegacy_pb2.LegacyMessage.SFM, self.handle_full_message_request)

        channel.register(qrllegacy_pb2.LegacyMessage.TX, self.handle_tx)
        channel.register(qrllegacy_pb2.LegacyMessage.TK, self.handle_token_transaction)
        channel.register(qrllegacy_pb2.LegacyMessage.TT, self.handle_transfer_token_transaction)
        channel.register(qrllegacy_pb2.LegacyMessage.MT, self.handle_message_transaction)
        channel.register(qrllegacy_pb2.LegacyMessage.LT, self.handle_lattice)
        channel.register(qrllegacy_pb2.LegacyMessage.SL, self.handle_slave)
        channel.register(qrllegacy_pb2.LegacyMessage.MC, self.handle_multi_sig_create)
        channel.register(qrllegacy_pb2.LegacyMessage.MS, self.handle_multi_sig_spend)
        channel.register(qrllegacy_pb2.LegacyMessage.MV, self.handle_multi_sig_vote)

    @staticmethod
    def handle_message_received(source, message: qrllegacy_pb2.LegacyMessage):
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
            if ntp.getTime() < source.factory.pow.suspend_mining_timestamp:
                return

            if source.factory._chain_manager.tx_pool.is_full_pending_transaction_pool():
                logger.warning('TX pool size full, incoming tx dropped. mr hash: %s', bin2hstr(msg_hash))
                return

        if mr_data.type == qrllegacy_pb2.LegacyMessage.BK:
            if mr_data.block_number > source.factory.chain_height + config.dev.max_margin_block_number:
                logger.debug('Skipping block #%s as beyond lead limit', mr_data.block_number)
                return
            if mr_data.block_number < source.factory.chain_height - config.dev.min_margin_block_number:
                logger.debug('Skipping block #%s as beyond the limit', mr_data.block_number)
                return

            if not source.factory.is_block_present(mr_data.prev_headerhash):
                logger.debug('Skipping block #%s as prev_headerhash not found', mr_data.block_number)
                return

        if source.factory.master_mr.contains(msg_hash, mr_data.type):
            return

        source.factory.master_mr.add_peer(msg_hash, mr_data.type, source, mr_data)

        if source.factory.master_mr.is_callLater_active(msg_hash):  # Ignore if already requested
            return

        source.factory.request_full_message(mr_data)

    @staticmethod
    def handle_full_message_request(source, message: qrllegacy_pb2.LegacyMessage):
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

    @staticmethod
    def handle_tx(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Transaction
        Executed whenever a new TX type message is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.TX)
        try:
            tx = Transaction.from_pbdata(message.txData)
        except Exception as e:
            logger.error('Message Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        # NOTE: Connects to MR
        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_message_transaction(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Message Transaction
        This function processes whenever a Transaction having
        subtype MESSAGE is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.MT)
        try:
            tx = Transaction.from_pbdata(message.mtData)
        except Exception as e:
            logger.error('Message Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_token_transaction(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Token Transaction
        This function processes whenever a Transaction having
        subtype TOKEN is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.TK)
        try:
            tx = Transaction.from_pbdata(message.tkData)
        except Exception as e:
            logger.error('Token Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_transfer_token_transaction(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Transfer Token Transaction
        This function processes whenever a Transaction having
        subtype TRANSFERTOKEN is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.TT)
        try:
            tx = Transaction.from_pbdata(message.ttData)
        except Exception as e:
            logger.error('Transfer Token Txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_lattice(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Lattice Public Key Transaction
        :param source:
        :param message:
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.LT)
        try:
            tx = Transaction.from_pbdata(message.ltData)
        except Exception as e:
            logger.error('lattice_public_key rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_slave(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Receives Slave Transaction
        :param source:
        :param message:
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.SL)
        try:
            tx = Transaction.from_pbdata(message.slData)
        except Exception as e:
            logger.error('slave_txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_multi_sig_create(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Handles Multi Sig Transaction
        :param source:
        :param message:
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.MC)
        try:
            tx = Transaction.from_pbdata(message.mcData)
        except Exception as e:
            logger.error('multi_sig_create txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_multi_sig_spend(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Handles Multi Sig Transaction
        :param source:
        :param message:
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.MS)
        try:
            tx = Transaction.from_pbdata(message.msData)
        except Exception as e:
            logger.error('multi_sig_spend txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)

    @staticmethod
    def handle_multi_sig_vote(source, message: qrllegacy_pb2.LegacyMessage):
        """
        Handles Multi Sig Transaction
        :param source:
        :param message:
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.MV)
        try:
            tx = Transaction.from_pbdata(message.mvData)
        except Exception as e:
            logger.error('multi_sig_vote txn rejected - unable to decode serialised data - closing connection')
            logger.exception(e)
            source.loseConnection()
            return

        if source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            source.factory.add_unprocessed_txn(tx, source.peer.ip)
