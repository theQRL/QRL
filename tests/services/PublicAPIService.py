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


class PublicAPITest(TestCase):
    def __init__(self, *args, **kwargs):
        super(PublicAPITest, self).__init__(*args, **kwargs)

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

    def test_getStats(self):
        db_state = Mock(spec=State)
        db_state.stake_validators_list = StakeValidatorsList()
        db_state.total_coin_supply = MagicMock(return_value=1000)

        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.nodeState = NodeState()
        p2p_factory.connections = 23
        p2p_factory.stake = False

        chain = Mock(spec=Chain)
        chain.height = MagicMock(return_value=0)
        chain.m_blockchain = []
        chain.m_get_block = MagicMock(return_value=None)
        chain.state = db_state

        qrlnode = QRLNode(db_state)
        qrlnode.set_p2pfactory(p2p_factory)
        qrlnode.set_chain(chain)

        service = PublicAPIService(qrlnode)
        stats = service.GetStats(request=qrl_pb2.GetStatsReq, context=None)

        # self.assertEqual(__version__, stats.node_info.version)  # FIXME
        self.assertEqual(qrl_pb2.NodeInfo.UNSYNCED, stats.node_info.state)
        self.assertEqual(23, stats.node_info.num_connections)
        # self.assertEqual("testnet", stats.node_info.network_id)  # FIXME

        self.assertEqual(0, stats.epoch)
        self.assertEqual(0, stats.uptime_network)

        self.assertEqual(0, stats.stakers_count)

        self.assertEqual(0, stats.block_last_reward)
        self.assertEqual(0, stats.block_time_mean)
        self.assertEqual(0, stats.block_time_sd)

        self.assertEqual(105000000, stats.coins_total_supply)
        self.assertEqual(1000, stats.coins_emitted)
        self.assertEqual(0, stats.coins_atstake)

        print(stats)

    def test_getKnownPeers(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        chain = Mock(spec=Chain)

        qrlnode = QRLNode(db_state)
        qrlnode.set_p2pfactory(p2p_factory)
        qrlnode.set_chain(chain)
        qrlnode.peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)
        response = service.GetKnownPeers(request=qrl_pb2.GetKnownPeersReq, context=None)

        self.assertEqual(2, len(response.known_peers.peers))
        self.assertEqual('127.0.0.1', response.known_peers.peers[0].ip)
        self.assertEqual('192.168.1.1', response.known_peers.peers[1].ip)

        print(response)

    def test_getAddressState(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        chain = Mock(spec=Chain)

        qrlnode = QRLNode(db_state)
        qrlnode.set_p2pfactory(p2p_factory)
        qrlnode.set_chain(chain)
        qrlnode.peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetAddressStateReq()
        response = service.GetAddressState(request=request, context=context)

        context.set_code.assert_called()
        context.set_details.assert_called()

        request = qrl_pb2.GetAddressStateReq()
        response = service.GetAddressState(request=request, context=context)
