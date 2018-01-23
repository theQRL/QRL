from pyqrllib.pyqrllib import bin2hstr

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
            if len(source.factory._chain_manager.tx_pool.pending_tx_pool) >= config.dev.transaction_pool_size:
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

        chain_manager = factory._chain_manager

        tx_state = chain_manager.state.get_address(address=tx.txfrom)

        is_valid_state = tx.validate_extended(tx_state=tx_state,
                                              transaction_pool=chain_manager.tx_pool.transaction_pool)
        return is_valid_state

    def handle_tx(self, source, message: qrllegacy_pb2.LegacyMessage):
        """
        Transaction
        Executed whenever a new TX type message is received.
        :return:
        """
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.TX)
        tx = Transaction.from_pbdata(message.txData)

        # NOTE: Connects to MR
        if not source.factory.master_mr.isRequested(tx.get_message_hash(), source):
            return

        self.process(source.factory, tx)

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
                    bin2hstr(block.headerhash))

        if not source.factory.master_mr.isRequested(block.headerhash, source, block):
            return

        source.factory.pow.pre_block_logic(block)  # FIXME: Ignores return value
        source.factory.master_mr.register(qrllegacy_pb2.LegacyMessage.BK, block.headerhash, message.block)

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
