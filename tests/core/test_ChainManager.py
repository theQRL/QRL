# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import mock, MagicMock, Mock
from pyqrllib.pyqrllib import hstr2bin
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core import config
from qrl.crypto.xmss import XMSS
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.Transaction import SlaveTransaction, TransferTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_default_balance_size, set_qrl_dir


class TestChainManager(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChainManager, self).__init__(*args, **kwargs)

    def test_load(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                genesis_block = GenesisBlock()
                chain_manager = ChainManager(state)
                chain_manager.load(genesis_block)
                block = state.get_block(GenesisBlock().headerhash)
                self.assertIsNotNone(block)

    def test_simple_add_block(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                state.get_measurement = MagicMock(return_value=10000000)
                alice_xmss = get_alice_xmss()

                genesis_block = GenesisBlock()
                chain_manager = ChainManager(state)
                chain_manager.load(genesis_block)

                chain_manager._difficulty_tracker = Mock()
                dt = DifficultyTracker()
                tmp_difficulty = StringToUInt256('2')
                tmp_target = dt.get_target(tmp_difficulty)
                chain_manager._difficulty_tracker.get = MagicMock(return_value=(tmp_difficulty, tmp_target))

                block = state.get_block(genesis_block.headerhash)
                self.assertIsNotNone(block)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1615270948  # Very high to get an easy difficulty

                    block_1 = Block.create(block_number=1,
                                           prev_block_headerhash=genesis_block.headerhash,
                                           prev_block_timestamp=genesis_block.timestamp,
                                           transactions=[],
                                           miner_address=alice_xmss.address)
                    block_1.set_nonces(22, 0)

                    # Uncomment only to determine the correct mining_nonce of above blocks
                    # from qrl.core.PoWValidator import PoWValidator
                    # while not PoWValidator().validate_mining_nonce(state, block_1.blockheader, False):
                    #     block_1.set_nonces(block_1.mining_nonce + 1)
                    #     print(block_1.mining_nonce)
                    self.assertTrue(block_1.validate(state, {}))
                    result = chain_manager.add_block(block_1)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_1)

    @set_default_balance_size()
    def test_multi_output_transaction_add_block(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                state.get_measurement = MagicMock(return_value=10000000)
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()
                extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                                "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
                random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))

                transfer_transaction = TransferTransaction.create(addrs_to=[alice_xmss.address, random_xmss.address],
                                                                  amounts=[40 * int(config.dev.shor_per_quanta),
                                                                           59 * int(config.dev.shor_per_quanta)],
                                                                  fee=1 * config.dev.shor_per_quanta,
                                                                  xmss_pk=bob_xmss.pk)
                transfer_transaction._data.nonce = 1
                transfer_transaction.sign(bob_xmss)

                genesis_block = GenesisBlock()
                chain_manager = ChainManager(state)
                chain_manager.load(genesis_block)

                chain_manager._difficulty_tracker = Mock()
                dt = DifficultyTracker()
                tmp_difficulty = StringToUInt256('2')
                tmp_boundary = dt.get_target(tmp_difficulty)
                chain_manager._difficulty_tracker.get = MagicMock(return_value=(tmp_difficulty, tmp_boundary))

                block = state.get_block(genesis_block.headerhash)
                self.assertIsNotNone(block)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1615270948  # Very high to get an easy difficulty

                    block_1 = Block.create(block_number=1,
                                           prev_block_headerhash=genesis_block.headerhash,
                                           prev_block_timestamp=genesis_block.timestamp,
                                           transactions=[transfer_transaction],
                                           miner_address=alice_xmss.address)
                    block_1.set_nonces(344, 0)

                    # Uncomment only to determine the correct mining_nonce of above blocks
                    # from qrl.core.PoWValidator import PoWValidator
                    # while not PoWValidator().validate_mining_nonce(state, block_1.blockheader, False):
                    #     block_1.set_nonces(block_1.mining_nonce + 1)
                    #     print(block_1.mining_nonce)
                    self.assertTrue(block_1.validate(state, {}))
                    result = chain_manager.add_block(block_1)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_1)

                bob_addr_state = state.get_address_state(bob_xmss.address)
                alice_addr_state = state.get_address_state(alice_xmss.address)
                random_addr_state = state.get_address_state(random_xmss.address)

                self.assertEqual(bob_addr_state.balance, 0)
                self.assertEqual(alice_addr_state.balance,
                                 140 * int(config.dev.shor_per_quanta) + block_1.block_reward + block_1.fee_reward)
                self.assertEqual(random_addr_state.balance, 159 * int(config.dev.shor_per_quanta))

    @mock.patch("qrl.core.DifficultyTracker.DifficultyTracker.get")
    def test_add_block(self, mock_difficulty_tracker_get):
        """
        Testing add_block, with fork logic
        :return:
        """
        with set_qrl_dir('no_data'):
            with State() as state:
                state.get_measurement = MagicMock(return_value=10000000)

                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                genesis_block = GenesisBlock()
                chain_manager = ChainManager(state)
                mock_difficulty_tracker_get.return_value = [config.dev.mining_setpoint_blocktime, 2]
                chain_manager.load(genesis_block)

                chain_manager._difficulty_tracker = Mock()
                tmp_difficulty = StringToUInt256('2')
                tmp_target = DifficultyTracker.get_target(tmp_difficulty)
                mock_difficulty_tracker_get.return_value = [tmp_difficulty, tmp_target]

                block = state.get_block(genesis_block.headerhash)
                self.assertIsNotNone(block)

                slave_tx = SlaveTransaction.create(slave_pks=[bob_xmss.pk],
                                                   access_types=[0],
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
                slave_tx.sign(alice_xmss)
                slave_tx._data.nonce = 1
                self.assertTrue(slave_tx.validate())
                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1615270948  # Very high to get an easy difficulty

                    block_1 = Block.create(block_number=1,
                                           prev_block_headerhash=genesis_block.headerhash,
                                           prev_block_timestamp=genesis_block.timestamp,
                                           transactions=[slave_tx],
                                           miner_address=alice_xmss.address)
                    block_1.set_nonces(3, 0)
                    # Uncomment only to determine the correct mining_nonce of above blocks
                    # from qrl.core.PoWValidator import PoWValidator
                    # while not PoWValidator().validate_mining_nonce(state, block_1.blockheader, False):
                    #     block_1.set_nonces(block_1.mining_nonce + 1)
                    #     print(block_1.mining_nonce)
                    self.assertTrue(block_1.validate(state, {}))
                    result = chain_manager.add_block(block_1)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_1)

                alice_state = chain_manager.get_address(alice_xmss.address)

                self.assertEqual(len(alice_state.slave_pks_access_type), 1)
                self.assertTrue(str(bob_xmss.pk) in alice_state.slave_pks_access_type)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1715270948  # Very high to get an easy difficulty
                    block = Block.create(block_number=1,
                                         prev_block_headerhash=genesis_block.headerhash,
                                         prev_block_timestamp=genesis_block.timestamp,
                                         transactions=[],
                                         miner_address=bob_xmss.address)

                    block.set_nonces(1, 0)
                    # Uncomment only to determine the correct mining_nonce of above blocks
                    # from qrl.core.PoWValidator import PoWValidator
                    # while not PoWValidator().validate_mining_nonce(state, block.blockheader, False):
                    #     block.set_nonces(block.mining_nonce + 1)
                    #     print(block.mining_nonce)
                    self.assertTrue(block.validate(state, {}))
                    result = chain_manager.add_block(block)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_1)

                block = state.get_block(block.headerhash)
                self.assertIsNotNone(block)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1815270948  # Very high to get an easy difficulty
                    block_2 = Block.create(block_number=2,
                                           prev_block_headerhash=block.headerhash,
                                           prev_block_timestamp=block.timestamp,
                                           transactions=[],
                                           miner_address=bob_xmss.address)

                    block_2.set_nonces(1, 0)
                    # Uncomment only to determine the correct mining_nonce of above blocks
                    # from qrl.core.PoWValidator import PoWValidator
                    # while not PoWValidator().validate_mining_nonce(state, block_2.blockheader, False):
                    #     block_2.set_nonces(block_2.mining_nonce + 1, 0)
                    #     print(block_2.mining_nonce)
                    self.assertTrue(block_2.validate(state, {}))
                    result = chain_manager.add_block(block_2)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block.block_number, block_2.block_number)
                self.assertEqual(chain_manager.last_block.to_json(), block_2.to_json())
