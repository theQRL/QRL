# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, MagicMock, patch

from qrl.core.Block import Block
from qrl.core.BlockHeader import BlockHeader
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.ChainManager import ChainManager
from qrl.core.misc import logger
from qrl.core.node import SyncState
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.crypto.misc import sha256
from qrl.generated import qrlmining_pb2
from qrl.services.MiningAPIService import MiningAPIService
from tests.misc.helper import replacement_getTime

logger.initialize_default()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestMiningAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMiningAPI, self).__init__(*args, **kwargs)

    def test_GetBlockMiningCompatible(self):
        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.sync_state = SyncState()
        p2p_factory.num_connections = 23
        p2p_factory.pow = Mock()

        chain_manager = Mock(spec=ChainManager)
        chain_manager.height = 0
        chain_manager.get_last_block = MagicMock(return_value=Block())

        qrlnode = QRLNode(mining_address=b'')
        qrlnode.set_chain_manager(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow

        block_header = BlockHeader.create(
            blocknumber=10,
            prev_headerhash=sha256(b'prevblock'),
            prev_timestamp=1234567890,
            hashedtransactions=sha256(b'tx1'),
            fee_reward=1)

        qrlnode.get_blockheader_and_metadata = MagicMock(return_value=[block_header, BlockMetadata()])

        service = MiningAPIService(qrlnode)
        req = qrlmining_pb2.GetBlockMiningCompatibleReq(height=10)

        answer = service.GetBlockMiningCompatible(request=req, context=None)

        self.assertEqual(10, answer.blockheader.block_number)
        self.assertEqual(1, answer.blockheader.reward_fee)
