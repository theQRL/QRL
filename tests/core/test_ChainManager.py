# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock

from qrl.core.Block import Block
from qrl.core.State import State
from qrl.core.Miner import Miner
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from tests.misc.helper import destroy_state, get_alice_xmss, get_bob_xmss


class TestChainManager(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChainManager, self).__init__(*args, **kwargs)

    def test_load(self):
        destroy_state()
        state = State()
        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)
        block = state.get_block(GenesisBlock().headerhash)
        self.assertIsNotNone(block)

    def test_add_block(self):
        """
        Testing add_block, with fork logic
        :return:
        """
        destroy_state()
        state = State()
        miner = Miner(Mock())

        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)
        chain_manager.set_miner(miner)


        block = state.get_block(genesis_block.headerhash)
        self.assertIsNotNone(block)

        alice_xmss = get_alice_xmss()

        block_1 = Block.create(mining_nonce=10,
                               block_number=1,
                               prevblock_headerhash=genesis_block.headerhash,
                               transactions=[],
                               signing_xmss=alice_xmss,
                               nonce=1)

        result = chain_manager.add_block(block_1)
        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_1)

        bob_xmss = get_bob_xmss()

        block = Block.create(mining_nonce=15,
                             block_number=1,
                             prevblock_headerhash=genesis_block.headerhash,
                             transactions=[],
                             signing_xmss=bob_xmss,
                             nonce=1)

        result = chain_manager.add_block(block)
        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_1)

        block = state.get_block(block.headerhash)
        self.assertIsNotNone(block)

        block_2 = Block.create(mining_nonce=15,
                               block_number=2,
                               prevblock_headerhash=block.headerhash,
                               transactions=[],
                               signing_xmss=bob_xmss,
                               nonce=2)

        result = chain_manager.add_block(block_2)

        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_2)

    def test_orphan_block(self):
        """
        Testing add_block logic in case of orphan_blocks
        :return:
        """
        destroy_state()
        state = State()
        miner = Mock()
        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)
        chain_manager.set_miner(miner)

        block = state.get_block(genesis_block.headerhash)
        self.assertIsNotNone(block)
        alice_xmss = get_alice_xmss()

        block_1 = Block.create(mining_nonce=10,
                               block_number=1,
                               prevblock_headerhash=genesis_block.headerhash,
                               transactions=[],
                               signing_xmss=alice_xmss,
                               nonce=1)
        block_1.set_mining_nonce(10)
        result = chain_manager.add_block(block_1)
        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_1)

        bob_xmss = get_bob_xmss()

        block = Block.create(mining_nonce=15,
                             block_number=1,
                             prevblock_headerhash=genesis_block.headerhash,
                             transactions=[],
                             signing_xmss=bob_xmss,
                             nonce=1)

        block.set_mining_nonce(15)

        block_2 = Block.create(mining_nonce=15,
                               block_number=2,
                               prevblock_headerhash=block.headerhash,
                               transactions=[],
                               signing_xmss=bob_xmss,
                               nonce=2)
        block_2.set_mining_nonce(15)

        result = chain_manager.add_block(block_2)
        self.assertFalse(result)
        result = chain_manager.add_block(block)
        self.assertTrue(result)
        block = state.get_block(block.headerhash)
        self.assertIsNotNone(block)

        self.assertEqual(chain_manager.last_block.block_number, block_2.block_number)
        self.assertEqual(chain_manager.last_block.headerhash, block_2.headerhash)

    def test_diff(self):
        from pyqryptonight.pyqryptonight import StringToUInt256
        diff = StringToUInt256("2")
        new_diff, target = Miner.calc_difficulty(120, 0, diff)
        new_diff, target = Miner.calc_difficulty(120, 0, new_diff)
        pass