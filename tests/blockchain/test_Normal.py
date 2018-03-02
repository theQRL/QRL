# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger
from tests.blockchain.MockedBlockchain import MockedBlockchain

logger.initialize_default()


class TestBlockchain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBlockchain, self).__init__(*args, **kwargs)

    def test_10blocks(self):
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            last_block = mock_blockchain.qrlnode.get_block_last()
            self.assertEqual(10, last_block.block_number)

    def test_11blocks(self):
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            last_block = mock_blockchain.qrlnode.get_block_last()
            self.assertEqual(10, last_block.block_number)

            mock_blockchain.add_new_block()
            last_block = mock_blockchain.qrlnode.get_block_last()
            self.assertEqual(11, last_block.block_number)

    def test_sequential_index(self):
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            block = mock_blockchain.qrlnode.get_block_last()

            while block is not None:
                prev_block = mock_blockchain.qrlnode.get_block_from_hash(block.prev_headerhash)
                if prev_block:
                    self.assertEqual(block.block_number - 1, prev_block.block_number)
                block = prev_block

    def test_get_by_index(self):
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            block = mock_blockchain.qrlnode.get_block_last()

            while block is not None:
                prev_block = mock_blockchain.qrlnode.get_block_from_hash(block.prev_headerhash)
                if prev_block:
                    self.assertEqual(prev_block.block_number + 1, block.block_number)

                    block_from_index = mock_blockchain.qrlnode.get_block_from_index(block.block_number)
                    self.assertEqual(block._data, block_from_index._data)

                block = prev_block

    def test_MockChain_forking(self):
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            block_5 = mock_blockchain.qrlnode.get_block_from_index(9)
            block_6b = mock_blockchain.create_block(block_5.headerhash)
            mock_blockchain.add_block(block_6b)
