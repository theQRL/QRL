# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, patch

from qrl.core import config
from qrl.core.ESyncState import ESyncState
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.misc import logger
from qrl.core.notification.Observable import Observable
from qrl.core.notification.ObservableEvent import ObservableEvent
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.p2p.p2pTxManagement import P2PTxManagement
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.generated import qrl_pb2, qrllegacy_pb2
from tests.misc.helper import get_some_address

logger.initialize_default()


def make_message(**kwargs):
    return qrllegacy_pb2.LegacyMessage(**kwargs)


class TestP2PTxManagement(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PTxManagement, self).__init__(*args, **kwargs)

    def test_count_registrations(self):
        channel = Mock()
        channel.register = Mock()

        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)
        channel.register.assert_called()

        self.assertEquals(11, channel.register.call_count)

    def test_observable(self):
        channel = Observable(None)
        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)
        self.assertEquals(11, channel.observers_count)

    def test_notification_no_observer(self):
        source = Mock()
        channel = Observable(source)

        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)

        event = ObservableEvent("event_id")

        with self.assertRaisesRegexp(RuntimeError, "Observer not registered for"):
            channel.notify(event, force_delivery=True)

    def test_notification(self):
        source = Mock()
        source.factory = Mock()
        source.factory.master_mr = Mock()
        source.factory.master_mr.isRequested = Mock()
        source.factory.add_unprocessed_txn = Mock()

        channel = Observable(source)

        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)

        tx = TransferTransaction.create(
            addrs_to=[get_some_address()],
            amounts=[1],
            message_data=None,
            fee=10,
            xmss_pk=bytes(67))

        event = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.TX,
                                            txData=tx.pbdata)

        channel.notify(event, force_delivery=True)
        source.factory.master_mr.isRequested.assert_called()
        source.factory.add_unprocessed_txn.assert_called()

    @patch('qrl.core.p2p.p2pTxManagement.logger')
    def test_bad_tx(self, mock_logger):
        source = Mock()
        source.factory = Mock()
        source.factory.master_mr = Mock()
        source.factory.master_mr.isRequested = Mock()
        source.factory.add_unprocessed_txn = Mock()

        channel = Observable(source)

        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)

        tx = SlaveTransaction.create(
            slave_pks=[],
            access_types=[],
            fee=1,
            xmss_pk=bytes(67))

        event = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.TX,
                                            txData=tx.pbdata)

        channel.notify(event, force_delivery=True)
        source.factory.master_mr.isRequested.assert_not_called()
        source.factory.add_unprocessed_txn.assert_not_called()


class TestP2PTxManagementHandlers(TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setUp(self):
        self.channel = Mock(autospec=P2PProtocol)
        self.channel.factory = Mock(autospec=P2PFactory)
        self.channel.factory.pow = Mock()
        self.channel.factory.pow.suspend_mining_timestamp = 0
        self.channel.factory.master_mr = Mock(autospec=MessageReceipt)

    def tearDown(self):
        del self.channel

    def test_handle_message_received(self):
        """
        handle_message_received() handles MessageReceipts. MessageReceipts are metadata for Messages, so peers know
        which peer has which blocks/transactions/whatever, but can request the full Message at their discretion.
        :return:
        """
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)

        # No, we do not already have this particular TX.
        self.channel.factory.master_mr.contains.return_value = False
        # No, we have not already requested the Message behind this MessageReceipt.
        self.channel.factory.master_mr.is_callLater_active.return_value = False

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_called_once_with(mrData)

    def test_handle_message_received_ignores_unknown_message_types(self):
        mrData = qrllegacy_pb2.MRData(type=999)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_not_called()

    def test_handle_message_received_transactions_ignored_while_unsynced(self):
        self.channel.factory.sync_state.state = ESyncState.syncing

        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.TX)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_not_called()

    @patch('qrl.core.p2p.p2pTxManagement.logger')
    def test_handle_message_received_transactions_ignored_while_mempool_full(self, mock_logger):
        self.channel.factory.sync_state.state = ESyncState.synced
        self.channel.factory.master_mr.contains.return_value = False  # No, we do not already have this Message.
        self.channel.factory.master_mr.is_callLater_active.return_value = False  # No, we haven't requested this Message yet.

        # First, test when the mempool is NOT full
        self.channel.factory._chain_manager.tx_pool.is_full_pending_transaction_pool.return_value = False
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.TX)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_called()

        # Now, test when the mempool IS full
        self.channel.factory.request_full_message.reset_mock()
        self.channel.factory._chain_manager.tx_pool.is_full_pending_transaction_pool.return_value = True

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_not_called()

    def test_handle_message_received_ignores_messages_it_already_has(self):
        self.channel.factory.master_mr.contains.return_value = True

        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_not_called()

    def test_handle_message_received_ignores_messages_it_already_has_requested(self):
        self.channel.factory.master_mr.contains.return_value = False  # No, we don't have this message yet.
        self.channel.factory.master_mr.is_callLater_active.return_value = True  # Yes, we have requested it.

        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)

        P2PTxManagement.handle_message_received(self.channel, msg)

        self.channel.factory.request_full_message.assert_not_called()

    def test_handle_message_received_ignores_blocks(self):
        """
        handle_message_received() should ignore MessageReceipts for blocks that are too far away from our current block
        height, or if it's an orphan block.
        """
        self.channel.factory.chain_height = 10  # Right now, our node is on block 10.
        self.channel.factory.master_mr.contains.return_value = False  # No, we do not already have this Message.
        self.channel.factory.master_mr.is_callLater_active.return_value = False  # No, we haven't requested this Message yet.

        # Ignore blocks that are config.dev_max_margin_block_number ahead.
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.BK,
                                      block_number=10 + config.dev.max_margin_block_number + 1)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)
        P2PTxManagement.handle_message_received(self.channel, msg)
        self.channel.factory.request_full_message.assert_not_called()

        # Ignore blocks that are config.dev_min_margin_block_number behind
        msg.mrData.block_number = 2
        P2PTxManagement.handle_message_received(self.channel, msg)
        self.channel.factory.request_full_message.assert_not_called()

        msg.mrData.block_number = 10  # Yes, it's another block 10!
        self.channel.factory.is_block_present.return_value = False  # But we don't have its previous block.
        P2PTxManagement.handle_message_received(self.channel, msg)
        self.channel.factory.request_full_message.assert_not_called()

        msg.mrData.block_number = 11  # now we have a follow-up block.
        self.channel.factory.is_block_present.return_value = True  # We do have its previous block.
        P2PTxManagement.handle_message_received(self.channel, msg)
        self.channel.factory.request_full_message.assert_called_once_with(msg.mrData)

    def test_handle_full_message_request(self):
        """
        A peer has requested a full message that corresponds to a MessageReceipt.
        This function checks if we actually have the full message for the given hash.
        If it does, send to peer, otherwise ignore.
        """

        # We do have the Message the peer requested.
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL)
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MR, mrData=mrData)
        P2PTxManagement.handle_full_message_request(self.channel, msg)
        self.channel.send.assert_called()

        # We don't have the Message the peer requested.
        self.channel.send.reset_mock()
        self.channel.factory.master_mr.get.return_value = None
        P2PTxManagement.handle_full_message_request(self.channel, msg)
        self.channel.send.assert_not_called()

    @patch('qrl.core.p2p.p2pTxManagement.Transaction')
    def test_handle_message_transaction(self, m_Transaction):
        """
        This handler handles a MessageTransaction type Transaction.
        :param m_Transaction:
        :return:
        """
        m_Transaction.from_pbdata.return_value = Mock(autospec=MessageTransaction, txhash=b'12345')
        self.channel.factory.master_mr.isRequested.return_value = True  # Yes, this is a Message which we have requested
        self.channel.factory.buffered_chain.tx_pool.pending_tx_pool_hash = []  # No, we haven't processed this TX before

        mtData = qrl_pb2.Transaction()
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MT, mtData=mtData)

        P2PTxManagement.handle_message_transaction(self.channel, msg)

        self.channel.factory.add_unprocessed_txn.assert_called()

        # What if we ended up parsing a Transaction that we never requested in the first place?
        self.channel.factory.add_unprocessed_txn.reset_mock()
        self.channel.factory.master_mr.isRequested.return_value = False
        P2PTxManagement.handle_message_transaction(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_not_called()

    @patch('qrl.core.p2p.p2pTxManagement.logger')
    @patch('qrl.core.p2p.p2pTxManagement.Transaction')
    def test_handle_message_transaction_invalid_transaction(self, m_Transaction, logger):
        """
        If the Transaction was so malformed that parsing it caused an exception, the peer should be disconnected.
        :param m_Transaction:
        :param logger:
        :return:
        """
        m_Transaction.from_pbdata.side_effect = Exception

        mtData = qrl_pb2.Transaction()
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.MT, mtData=mtData)

        P2PTxManagement.handle_message_transaction(self.channel, msg)

        self.channel.loseConnection.assert_called()


@patch('qrl.core.p2p.p2pTxManagement.logger')
@patch('qrl.core.p2p.p2pTxManagement.Transaction')
class TestP2PTxManagementSimpleHandlers(TestCase):
    def setUp(self):
        self.channel = Mock(autospec=P2PProtocol)
        self.channel.factory = Mock(autospec=P2PFactory)
        self.channel.factory.master_mr = Mock(autospec=MessageReceipt)

        self.channel.factory.master_mr.isRequested.return_value = True

    def tearDown(self):
        del self.channel

    def test_handle_token_transaction(self, m_Transaction, m_logger):
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.TK, tkData=qrl_pb2.Transaction())
        P2PTxManagement.handle_token_transaction(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_called()

    def test_handle_token_transaction_error_parsing_transaction(self, m_Transaction, m_logger):
        m_Transaction.from_pbdata.side_effect = Exception
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.TK, tkData=qrl_pb2.Transaction())
        P2PTxManagement.handle_token_transaction(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_not_called()
        m_logger.exception.assert_called()
        self.channel.loseConnection.assert_called()

    def test_handle_transfer_token_transaction(self, m_Transaction, m_logger):
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.TT, ttData=qrl_pb2.Transaction())
        P2PTxManagement.handle_transfer_token_transaction(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_called()

    def test_handle_transfer_token_transaction_error_parsing_transaction(self, m_Transaction, m_logger):
        m_Transaction.from_pbdata.side_effect = Exception
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.TT, ttData=qrl_pb2.Transaction())
        P2PTxManagement.handle_transfer_token_transaction(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_not_called()
        m_logger.exception.assert_called()
        self.channel.loseConnection.assert_called()

    def test_handle_lattice(self, m_Transaction, m_logger):
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.LT, ltData=qrl_pb2.Transaction())
        P2PTxManagement.handle_lattice(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_called()

    def test_handle_lattice_error_parsing_transaction(self, m_Transaction, m_logger):
        m_Transaction.from_pbdata.side_effect = Exception
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.LT, ltData=qrl_pb2.Transaction())
        P2PTxManagement.handle_lattice(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_not_called()
        m_logger.exception.assert_called()
        self.channel.loseConnection.assert_called()

    def test_handle_slave(self, m_Transaction, m_logger):
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.SL, slData=qrl_pb2.Transaction())
        P2PTxManagement.handle_slave(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_called()

    def test_handle_slave_error_parsing_transaction(self, m_Transaction, m_logger):
        m_Transaction.from_pbdata.side_effect = Exception
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.SL, slData=qrl_pb2.Transaction())
        P2PTxManagement.handle_slave(self.channel, msg)
        self.channel.factory.add_unprocessed_txn.assert_not_called()
        m_logger.exception.assert_called()
        self.channel.loseConnection.assert_called()
