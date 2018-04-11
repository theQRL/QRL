# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock

from qrl.core.Transaction import TransferTransaction, SlaveTransaction
from qrl.core.misc import logger
from qrl.core.notification.Observable import Observable
from qrl.core.notification.ObservableEvent import ObservableEvent
from qrl.core.p2p.p2pTxManagement import P2PTxManagement
from qrl.generated import qrllegacy_pb2

logger.initialize_default()


class TestP2PTxManagement(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PTxManagement, self).__init__(*args, **kwargs)

    def test_count_registrations(self):
        channel = Mock()
        channel.register = Mock()

        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)
        channel.register.assert_called()

        self.assertEquals(9, channel.register.call_count)

    def test_observable(self):
        channel = Observable(None)
        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)
        self.assertEquals(9, channel.observers_count)

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

        tx = TransferTransaction.create([], [0], 10, xmss_pk=bytes(40))

        event = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.TX,
                                            txData=tx.pbdata)

        channel.notify(event, force_delivery=True)
        source.factory.master_mr.isRequested.assert_called()
        source.factory.add_unprocessed_txn.assert_called()

    def test_bad_tx(self):
        source = Mock()
        source.factory = Mock()
        source.factory.master_mr = Mock()
        source.factory.master_mr.isRequested = Mock()
        source.factory.add_unprocessed_txn = Mock()

        channel = Observable(source)

        self.tx_manager = P2PTxManagement()
        self.tx_manager.new_channel(channel)

        tx = SlaveTransaction.create([], [], 1, bytes(100))
        event = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.TX,
                                            txData=tx.pbdata)

        channel.notify(event, force_delivery=True)
        source.factory.master_mr.isRequested.assert_not_called()
        source.factory.add_unprocessed_txn.assert_not_called()
