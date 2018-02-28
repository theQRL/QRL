# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import sha2_256

from tests.misc.helper import get_alice_xmss
from qrl.core.misc import logger
from qrl.core.Block import Block

logger.initialize_default()


class TestBlock(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBlock, self).__init__(*args, **kwargs)

    def test_init(self):
        # TODO: Not much going on here..
        block = Block()
        self.assertIsNotNone(block)             # just to avoid warnings

    def test_from_blob(self):
        alice_xmss = get_alice_xmss()
        block = Block.create(block_number=5,
                             prevblock_headerhash=bytes(sha2_256(b'test')),
                             transactions=[],
                             signing_xmss=alice_xmss,
                             master_address=alice_xmss.address,
                             nonce=10)
        mining_blob = block.mining_blob
        block_header = block.blockheader.from_blob(mining_blob)
        self.assertEqual(block_header.block_number, block.block_number)
        self.assertEqual(block_header.timestamp, block.timestamp)
        self.assertEqual(block_header.prev_blockheaderhash, block.prev_headerhash)
        self.assertEqual(block_header.block_reward, block.block_reward)
        self.assertEqual(block_header.fee_reward, block.fee_reward)
        self.assertEqual(block_header.tx_merkle_root, block.blockheader.tx_merkle_root)
        self.assertEqual(block_header.PK, block.blockheader.PK)
        self.assertEqual(block_header.mining_nonce, block.mining_nonce)
        self.assertEqual(block_header.headerhash, block.headerhash)
