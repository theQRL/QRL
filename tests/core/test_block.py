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

    def test_verify_blob(self):
        alice_xmss = get_alice_xmss()
        block = Block.create(block_number=5,
                             prevblock_headerhash=bytes(sha2_256(b'test')),
                             transactions=[],
                             miner_address=alice_xmss.address)
        mining_blob = block.mining_blob
        self.assertTrue(block.blockheader.verify_blob(mining_blob))

    def test_set_mining_nonce_from_blob(self):
        alice_xmss = get_alice_xmss()
        block = Block.create(block_number=5,
                             prevblock_headerhash=bytes(sha2_256(b'test')),
                             transactions=[],
                             miner_address=alice_xmss.address)
        current_mining_nonce = block.mining_nonce
        current_headerhash = block.headerhash
        mining_blob = block.mining_blob
        block.blockheader.set_mining_nonce_from_blob(mining_blob)
        self.assertEqual(block.blockheader.mining_nonce, current_mining_nonce)
        self.assertEqual(block.headerhash, current_headerhash)
        self.assertEqual(block.blockheader.mining_blob, mining_blob)
