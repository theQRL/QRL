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

    def test_forking_basic(self):
        """
        TODO: Cyyber review
        - Create a blockchain of 10 blocks
        - Add a new block 10b (linking to 9)
        - Check that it did not switch
        """
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            # Fork at node 9
            block_9 = mock_blockchain.qrlnode.get_block_from_index(9)
            block_10 = mock_blockchain.qrlnode.get_block_last()
            block_10b = mock_blockchain.create_block(block_9.headerhash)

            self.assertEqual(block_9.headerhash, block_10.prev_headerhash)
            self.assertEqual(block_9.headerhash, block_10b.prev_headerhash)

            # Add a new block pointing to 9
            mock_blockchain.add_block(block_10b)

            last_block = mock_blockchain.qrlnode.get_block_last()
            block_index_10 = mock_blockchain.qrlnode.get_block_from_index(10)

            self.assertEqual(last_block._data, block_index_10._data)
            self.assertEqual(last_block._data, block_10._data)
            self.assertNotEquals(last_block._data, block_10b._data)

    def test_forking_basic2(self):
        """
        TODO: Cyyber review
        - Create a blockchain of 10 blocks
        - Add a new blocks 10b, 11b (linking from 9)
        - Check that it did switch
        """
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            # Fork at node 9
            block_9 = mock_blockchain.qrlnode.get_block_from_index(9)

            # Fork with 2 blocks
            block_10b = mock_blockchain.create_block(block_9.headerhash)
            mock_blockchain.add_block(block_10b)
            block_11b = mock_blockchain.create_block(block_10b.headerhash)
            mock_blockchain.add_block(block_11b)

            last_block = mock_blockchain.qrlnode.get_block_last()
            print(last_block.block_number)
            block_index_10 = mock_blockchain.qrlnode.get_block_from_index(10)
            block_index_11 = mock_blockchain.qrlnode.get_block_from_index(11)

            self.assertEqual(block_10b._data, block_index_10._data)
            self.assertEqual(last_block._data, block_index_11._data)
            self.assertEqual(last_block._data, block_11b._data)

    def test_forking_basic3(self):
        """
        TODO: Cyyber review
        - Create a blockchain of 10 blocks
        - Add a new blocks 10b, 11b (linking from 9)
        - Check that it did switch
        - Add a new blocks 11, 12 (linking from 10)
        - Check that it did switch again
        """
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            # Fork at node 9
            block_9 = mock_blockchain.qrlnode.get_block_from_index(9)
            block_10 = mock_blockchain.qrlnode.get_block_last()

            # Fork with 2 blocks (b)
            block_10b = mock_blockchain.create_block(block_9.headerhash)
            mock_blockchain.add_block(block_10b)
            block_11b = mock_blockchain.create_block(block_10b.headerhash)
            mock_blockchain.add_block(block_11b)

            # Check
            last_block = mock_blockchain.qrlnode.get_block_last()
            block_index_10 = mock_blockchain.qrlnode.get_block_from_index(10)
            block_index_11 = mock_blockchain.qrlnode.get_block_from_index(11)
            self.assertEqual(block_10b._data, block_index_10._data)
            self.assertEqual(last_block._data, block_index_11._data)
            self.assertEqual(last_block._data, block_11b._data)

            # Add back to the original chain (a)
            block_11 = mock_blockchain.create_block(block_10.headerhash)
            mock_blockchain.add_block(block_11)
            block_12 = mock_blockchain.create_block(block_11.headerhash)
            mock_blockchain.add_block(block_12)

            # Check
            last_block = mock_blockchain.qrlnode.get_block_last()
            block_index_10 = mock_blockchain.qrlnode.get_block_from_index(10)
            block_index_11 = mock_blockchain.qrlnode.get_block_from_index(11)
            block_index_12 = mock_blockchain.qrlnode.get_block_from_index(12)
            self.assertEqual(block_10._data, block_index_10._data)
            self.assertEqual(block_11._data, block_index_11._data)
            self.assertEqual(last_block._data, block_index_12._data)
            self.assertEqual(last_block._data, block_12._data)
