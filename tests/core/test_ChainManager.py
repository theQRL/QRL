# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading
from unittest import TestCase

from mock import Mock

from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Miner import Miner
from qrl.core.State import State
from tests.misc.helper import destroy_state, get_alice_xmss, get_bob_xmss, read_data_file


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
        miner = Miner(Mock(), Mock())

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
        from pyqryptonight.pyqryptonight import Qryptominer

        class CustomQMiner(Qryptominer):
            def __init__(self):
                Qryptominer.__init__(self)
                self._solution_lock = threading.Lock()
                self.nonce = None

            def start(self, threads):
                self.cancel()
                try:
                    self._solution_lock.release()
                except RuntimeError:
                    pass
                self._solution_lock.acquire(blocking=False)
                super().start(threads)

            def wait_for_solution(self):
                self._solution_lock.acquire(blocking=True)
                self._solution_lock.release()

            def solutionEvent(self, nonce):
                print('Solution Found %s', nonce)
                self.nonce = nonce
                self._solution_lock.release()

        block_timestamp = 1515443508
        parent_block_timestamp = 1515443508
        parent_difficulty = (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4)
        new_diff, new_target = Miner.calc_difficulty(block_timestamp, parent_timestamp=parent_block_timestamp,
                                                     parent_difficulty=parent_difficulty)
        self.assertEqual(new_diff, (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6))
        self.assertEqual(new_target, (
            42, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170))

        block_json = read_data_file('core/example_block_mining.json')

        block = Block.from_json(block_json)
        self.assertEqual(tuple(block.mining_hash), (
            186, 155, 236, 133, 247, 194, 196, 56, 208, 139, 175, 190, 149, 30, 119, 56, 146, 137, 223, 27, 167, 199,
            76,
            131, 237, 152, 160, 251, 168, 78, 77, 181))
        input_bytes = [0, 0, 0, 6, 186, 155, 236, 133, 247, 194, 196, 56, 208, 139, 175, 190, 149, 30, 119, 56, 146,
                       137, 223, 27, 167, 199, 76, 131, 237, 152, 160, 251, 168, 78, 77, 181]
        custom_qminer = CustomQMiner()
        custom_qminer.setInput(input=input_bytes,
                               nonceOffset=0,
                               target=new_target)
        custom_qminer.start(2)
        custom_qminer.wait_for_solution()

        print(custom_qminer.nonce)
        self.assertTrue(custom_qminer.verifyInput(input_bytes, new_target))
