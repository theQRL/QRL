# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import pytest
from grpc import ServicerContext
from grpc._server import _Context
from mock import Mock, MagicMock, __version__

from qrl.core import logger
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.StakeValidatorsList import StakeValidatorsList
from qrl.core.chain import Chain
from qrl.core.node import NodeState
from qrl.core.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.core.state import State
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService

logger.initialize_default(force_console_output=True)


class CommonAPITest(TestCase):
    def __init__(self, *args, **kwargs):
        super(CommonAPITest, self).__init__(*args, **kwargs)

    def test_getNodeState(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.nodeState = NodeState()
        p2p_factory.connections = 23
        p2p_factory.stake = False

        chain = Mock(spec=Chain)
        chain.height = MagicMock(return_value=0)

        qrlnode = QRLNode(db_state)
        qrlnode.set_p2pfactory(p2p_factory)
        qrlnode.set_chain(chain)

        service = PublicAPIService(qrlnode)
        node_state = service.GetNodeState(request=qrl_pb2.GetNodeStateReq, context=None)

        # self.assertEqual(__version__, node_state.info.version)  # FIXME
        self.assertEqual(qrl_pb2.NodeInfo.UNSYNCED, node_state.info.state)
        self.assertEqual(23, node_state.info.num_connections)
        # self.assertEqual("testnet", node_state.info.network_id)  # FIXME

    def test_getKnownPeers(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        chain = Mock(spec=Chain)

        qrlnode = QRLNode(db_state)
        qrlnode.set_p2pfactory(p2p_factory)
        qrlnode.set_chain(chain)
        qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)
        response = service.GetKnownPeers(request=qrl_pb2.GetKnownPeersReq, context=None)

        self.assertEqual(2, len(response.known_peers.peers))
        self.assertEqual('127.0.0.1', response.known_peers.peers[0].ip)
        self.assertEqual('192.168.1.1', response.known_peers.peers[1].ip)

        print(response)
