# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from time import sleep
from unittest import TestCase

from mock import Mock, patch

from qrl.core import logger
from qrl.core.State import State
from qrl.core.qrlnode import QRLNode
from qrl.services.PeerManager import PeerManager

logger.initialize_default(force_console_output=True)


class TestPeerManager(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPeerManager, self).__init__(*args, **kwargs)

    def test_create(self):
        db_state = Mock(spec=State)
        qrlnode = QRLNode(db_state)

        with patch('qrl.generated.qrl_pb2_grpc.P2PAPIStub'):
            pm = PeerManager(qrlnode)
            self.assertIsNotNone(pm)
            self.assertEqual(0, pm.stable_peer_count)

            pm.add(['127.0.0.1'])
            pm.add(['0.0.0.0'])
            self.assertEqual(0, pm.peer_count)

            pm.add(['1.1.1.1'])
            self.assertEqual(1, pm.peer_count)
            self.assertEqual(0, pm.stable_peer_count)

            sleep(2)

    # TODO: Test discovery
