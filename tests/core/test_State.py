# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
import mock
from mock import MagicMock, patch

from qrl.core import config
from qrl.core.misc import logger, db
from qrl.core.State import State
from qrl.core.Block import Block
from qrl.generated import qrlstateinfo_pb2

from tests.misc.helper import set_qrl_dir, get_alice_xmss, replacement_getTime, gen_blocks

logger.initialize_default()


@mock.patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestState(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()
        self.m_db = MagicMock(name='mock DB', autospec=db.DB)

    def test_create_state(self):
        self.assertIsNotNone(self.state)  # to avoid warning (unused variable)

    def test_release_state(self):
        self.assertIsNotNone(self.state)  # to avoid warning (unused variable)

    def test_basic_state_funcs(self):
        batch = self.state.batch
        self.assertIsNotNone(batch)
        self.state.write_batch(batch)
        self.assertEqual(self.state.total_coin_supply, 0)

    def test_address_used(self):
        alice_xmss = get_alice_xmss()
        self.assertFalse(self.state.get_address_is_used(alice_xmss.address))

    def test_get_batch(self):
        self.assertIsNotNone(self.state.batch)

    def test_write_batch(self):
        batch = self.state.batch
        block = Block.create(dev_config=config.dev,
                             block_number=10,
                             prev_headerhash=b'aa',
                             prev_timestamp=10,
                             transactions=[],
                             miner_address=b'aa',
                             seed_height=0,
                             seed_hash=None)
        Block.put_block(self.state, block, batch)
        self.assertIsNone(Block.get_block(self.state, block.headerhash))
        self.state.write_batch(batch)
        block2 = Block.get_block(self.state, block.headerhash)
        self.assertEqual(block.headerhash, block2.headerhash)

    def test_update_total_coin_supply(self):
        self.assertEqual(self.state.total_coin_supply, 0)
        self.state._update_total_coin_supply(100, None)
        self.assertEqual(self.state.total_coin_supply, 100)

    def test_total_coin_supply(self):
        self.assertEqual(self.state.total_coin_supply, 0)

    def test_delete(self):
        block = Block()
        Block.put_block(self.state, block, None)
        block1 = Block.get_block(self.state, block.headerhash)
        self.assertEqual(block.serialize(), block1.serialize())
        self.state._delete(block.headerhash, None)
        self.assertIsNone(Block.get_block(self.state, block.headerhash))

    def test_get_block_size_limit(self):
        alice_xmss = get_alice_xmss()
        blocks = gen_blocks(20, self.state, alice_xmss.address)
        self.assertEqual(Block.get_block_size_limit(self.state, blocks[-1], config.dev), 1048576)

        # get_block_size_limit() should return None if it couldn't get any blocks from db
        with patch('qrl.core.Block.Block.get_block', return_value=None):
            self.assertIsNone(Block.get_block_size_limit(self.state, blocks[-1], config.dev))

    def test_update_mainchain_height(self):
        self.state.update_mainchain_height(5, None)
        self.assertEqual(self.state.get_mainchain_height(), 5)

    def test_get_mainchain_height(self):
        # Test Case: Check default value
        self.assertEqual(self.state.get_mainchain_height(), -1)

        self.state.update_mainchain_height(15, None)
        self.assertEqual(self.state.get_mainchain_height(), 15)

        self.state.update_mainchain_height(5, None)
        self.assertEqual(self.state.get_mainchain_height(), 5)

    def test_fork_state(self):
        fork_state = qrlstateinfo_pb2.ForkState(
            initiator_headerhash=b'block2_right',
            fork_point_headerhash=b'block0_base_of_fork',
            old_mainchain_hash_path=[b'block1_right', b'block2_right'],
            new_mainchain_hash_path=[b'block1_left', b'block2_left']
        )
        self.assertIsNone(self.state.get_fork_state())

        self.state.put_fork_state(fork_state)
        self.assertEqual(fork_state, self.state.get_fork_state())

        self.state.delete_fork_state()
        self.assertIsNone(self.state.get_fork_state())
