# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import mock

from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_data_dir


class TestChainManager(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChainManager, self).__init__(*args, **kwargs)

    def test_load(self):
        with set_data_dir('no_data'):
            with State() as state:
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
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                genesis_block = GenesisBlock()
                chain_manager = ChainManager(state)
                chain_manager.load(genesis_block)

                block = state.get_block(genesis_block.headerhash)
                self.assertIsNotNone(block)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1615270948  # Very high to get an easy difficulty

                    block_1 = Block.create(mining_nonce=10,
                                           block_number=1,
                                           prevblock_headerhash=genesis_block.headerhash,
                                           transactions=[],
                                           signing_xmss=alice_xmss,
                                           nonce=1)

                    while not chain_manager.validate_mining_nonce(block_1, False):
                        block_1.set_mining_nonce(block_1.mining_nonce + 1)

                    result = chain_manager.add_block(block_1)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_1)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1715270948  # Very high to get an easy difficulty
                    block = Block.create(mining_nonce=15,
                                         block_number=1,
                                         prevblock_headerhash=genesis_block.headerhash,
                                         transactions=[],
                                         signing_xmss=bob_xmss,
                                         nonce=1)

                    while not chain_manager.validate_mining_nonce(block, False):
                        block.set_mining_nonce(block.mining_nonce + 1)

                    result = chain_manager.add_block(block)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_1)

                block = state.get_block(block.headerhash)
                self.assertIsNotNone(block)

                with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                    time_mock.return_value = 1815270948  # Very high to get an easy difficulty
                    block_2 = Block.create(mining_nonce=15,
                                           block_number=2,
                                           prevblock_headerhash=block.headerhash,
                                           transactions=[],
                                           signing_xmss=bob_xmss,
                                           nonce=2)

                    while not chain_manager.validate_mining_nonce(block_2, False):
                        block_2.set_mining_nonce(block_2.mining_nonce + 1)

                    result = chain_manager.add_block(block_2)

                self.assertTrue(result)
                self.assertEqual(chain_manager.last_block, block_2)

    def test_orphan_block(self):
        """
        Testing add_block logic in case of orphan_blocks
        :return:
        """
        with mock.patch('qrl.core.config.DevConfig') as devconfig:
            devconfig.genesis_difficulty = 2
            devconfig.minimum_minting_delay = 10
            with set_data_dir('no_data'):
                with State() as state:  # FIXME: Move state to temporary directory
                    genesis_block = GenesisBlock()

                    chain_manager = ChainManager(state)
                    chain_manager.load(genesis_block)

                    block = state.get_block(genesis_block.headerhash)
                    self.assertIsNotNone(block)
                    alice_xmss = get_alice_xmss()

                    with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                        time_mock.return_value = 1615270948  # Very high to get an easy difficulty
                        block_1 = Block.create(mining_nonce=10,
                                               block_number=1,
                                               prevblock_headerhash=genesis_block.headerhash,
                                               transactions=[],
                                               signing_xmss=alice_xmss,
                                               nonce=1)
                        block_1.set_mining_nonce(10)

                        while not chain_manager.validate_mining_nonce(block_1, False):
                            block_1.set_mining_nonce(block_1.mining_nonce + 1)

                        result = chain_manager.add_block(block_1)

                    self.assertTrue(result)
                    self.assertEqual(chain_manager.last_block, block_1)

                    bob_xmss = get_bob_xmss()

                    with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                        time_mock.return_value = 1615270948 + devconfig.minimum_minting_delay * 2
                        block = Block.create(mining_nonce=18,
                                             block_number=1,
                                             prevblock_headerhash=genesis_block.headerhash,
                                             transactions=[],
                                             signing_xmss=bob_xmss,
                                             nonce=1)
                        block.set_mining_nonce(18)

                        while not chain_manager.validate_mining_nonce(block, False):
                            block.set_mining_nonce(block.mining_nonce + 1)

                    with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                        time_mock.return_value = 1615270948 + devconfig.minimum_minting_delay * 3
                        block_2 = Block.create(mining_nonce=17,
                                               block_number=2,
                                               prevblock_headerhash=block.headerhash,
                                               transactions=[],
                                               signing_xmss=bob_xmss,
                                               nonce=2)
                        block_2.set_mining_nonce(17)

                    result = chain_manager.add_block(block_2)
                    self.assertTrue(result)

                    result = chain_manager.add_block(block)
                    self.assertTrue(result)

                    block = state.get_block(block.headerhash)
                    self.assertIsNotNone(block)

                    self.assertEqual(chain_manager.last_block.block_number, block_1.block_number)
                    self.assertEqual(chain_manager.last_block.headerhash, block_1.headerhash)
