# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import grpc
from mock import Mock

from qrl.core import logger, BufferedChain, config
from qrl.core.State import State
from qrl.core.node import SyncState
from qrl.core.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.services.P2PAPIService import P2PAPIService

logger.initialize_default(force_console_output=True)


class TestPublicAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI, self).__init__(*args, **kwargs)
        self.service = None

    def setUp(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.sync_state = SyncState()
        p2p_factory.connections = 23
        p2p_factory.pos = Mock()
        p2p_factory.pos.stake = False

        buffered_chain = Mock(spec=BufferedChain)
        buffered_chain.height = 0

        qrlnode = QRLNode(db_state)
        qrlnode.set_p2pfactory(p2p_factory)
        qrlnode.set_chain(buffered_chain)
        qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

        self.service = P2PAPIService(qrlnode)

    def test_getNodeState(self):
        context = Mock(spec=grpc.ServicerContext)
        response = self.service.GetNodeState(request=qrl_pb2.GetNodeStateReq, context=context)
        context.set_code.assert_not_called()

        self.assertEqual(config.dev.version, response.info.version)
        self.assertEqual(qrl_pb2.NodeInfo.UNSYNCED, response.info.state)
        self.assertEqual(23, response.info.num_connections)
        # self.assertEqual("testnet", node_state.response.network_id)  # FIXME

    def test_getKnownPeers(self):
        context = Mock(spec=grpc.ServicerContext)
        response = self.service.GetKnownPeers(request=qrl_pb2.GetKnownPeersReq, context=context)
        context.set_code.assert_not_called()

        self.assertEqual(config.dev.version, response.node_info.version)
        self.assertEqual(qrl_pb2.NodeInfo.UNSYNCED, response.node_info.state)
        self.assertEqual(23, response.node_info.num_connections)
        # self.assertEqual("testnet", node_state.response.network_id)  # FIXME

        self.assertEqual(2, len(response.known_peers))
        self.assertEqual('127.0.0.1', response.known_peers[0].ip)
        self.assertEqual('192.168.1.1', response.known_peers[1].ip)
