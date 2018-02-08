# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import time
from unittest import TestCase

from mock import Mock, MagicMock, mock
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.Transaction import SlaveTransaction
from qrl.core.misc import logger
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from tests.misc.helper import get_alice_xmss, set_data_dir, get_bob_xmss

logger.initialize_default()


class TestPublicAPI2(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI2, self).__init__(*args, **kwargs)

    def test_getStats2(self):
        start_time = time.time()
        with mock.patch('qrl.core.misc.ntp.getTime') as ntp_mock, \
                set_data_dir('no_data'), \
                State() as state, \
                mock.patch('time.time') as time_mock:  # noqa
            time_mock.return_value = start_time
            ntp_mock.return_value = start_time

            state.get_measurement = MagicMock(return_value=10000000)

            alice_xmss = get_alice_xmss()
            bob_xmss = get_bob_xmss()

            genesis_block = GenesisBlock()
            chain_manager = ChainManager(state)
            chain_manager.load(genesis_block)

            chain_manager._difficulty_tracker = Mock()
            dt = DifficultyTracker()
            tmp_difficulty = StringToUInt256('2')
            tmp_boundary = dt.get_boundary(tmp_difficulty)
            chain_manager._difficulty_tracker.get = MagicMock(return_value=(tmp_difficulty, tmp_boundary))

            block = state.get_block(genesis_block.headerhash)
            self.assertIsNotNone(block)

            slave_tx = SlaveTransaction.create(addr_from=alice_xmss.get_address(),
                                               slave_pks=[bob_xmss.pk()],
                                               access_types=[0],
                                               fee=0,
                                               xmss_pk=alice_xmss.pk(),
                                               xmss_ots_index=alice_xmss.get_index())
            slave_tx.sign(alice_xmss)
            slave_tx._data.nonce = 2
            self.assertTrue(slave_tx.validate())

            block_1 = Block.create(mining_nonce=10,
                                   block_number=1,
                                   prevblock_headerhash=genesis_block.headerhash,
                                   transactions=[slave_tx],
                                   signing_xmss=alice_xmss,
                                   master_address=alice_xmss.get_address(),
                                   nonce=1)

            while not chain_manager.validate_mining_nonce(block_1, False):
                block_1.set_mining_nonce(block_1.mining_nonce + 1)

            result = chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(chain_manager.last_block, block_1)

            alice_state = chain_manager.get_address(alice_xmss.get_address())

            self.assertEqual(len(alice_state.slave_pks_access_type), 1)
            self.assertTrue(str(bob_xmss.pk()) in alice_state.slave_pks_access_type)

            time_mock.return_value = start_time + 120
            ntp_mock.return_value = start_time + 120

            block = Block.create(mining_nonce=15,
                                 block_number=1,
                                 prevblock_headerhash=genesis_block.headerhash,
                                 transactions=[],
                                 signing_xmss=bob_xmss,
                                 master_address=bob_xmss.get_address(),
                                 nonce=1)

            while not chain_manager.validate_mining_nonce(block, False):
                block.set_mining_nonce(block.mining_nonce + 1)

            result = chain_manager.add_block(block)

            self.assertTrue(result)
            self.assertEqual(chain_manager.last_block, block_1)

            block = state.get_block(block.headerhash)
            self.assertIsNotNone(block)

            time_mock.return_value = start_time + 170
            ntp_mock.return_value = start_time + 170

            block_2 = Block.create(mining_nonce=15,
                                   block_number=2,
                                   prevblock_headerhash=block.headerhash,
                                   transactions=[],
                                   signing_xmss=bob_xmss,
                                   master_address=bob_xmss.get_address(),
                                   nonce=2)

            while not chain_manager.validate_mining_nonce(block_2, False):
                block_2.set_mining_nonce(block_2.mining_nonce + 1)

            result = chain_manager.add_block(block_2)

            self.assertTrue(result)
            self.assertEqual(chain_manager.last_block.block_number, block_2.block_number)
            self.assertEqual(chain_manager.last_block.to_json(), block_2.to_json())

            qrlnode = QRLNode(state, slaves=[])
            qrlnode.set_chain_manager(chain_manager)
            # qrlnode._p2pfactory = p2p_factory
            # qrlnode._pow = p2p_factory.pow

            service = PublicAPIService(qrlnode)
            request = qrl_pb2.GetStatsReq()
            request.include_timeseries = True

            stats = service.GetStats(request=request, context=None)

            self.assertEqual(3, len(stats.block_timeseries))

            logger.info(stats)
