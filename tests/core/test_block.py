# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from mock import patch
from pyqrllib.pyqrllib import sha2_256

from tests.misc.helper import get_alice_xmss, get_bob_xmss
from qrl.core import config
from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.crypto.misc import merkle_tx_hash

from tests.misc.helper import replacement_getTime

logger.initialize_default()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestBlock(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBlock, self).__init__(*args, **kwargs)

    def test_init(self):
        # TODO: Not much going on here..
        block = Block()
        self.assertIsNotNone(block)  # just to avoid warnings

    def test_verify_blob(self):
        alice_xmss = get_alice_xmss()
        block = Block.create(block_number=5,
                             prev_headerhash=bytes(sha2_256(b'test')),
                             prev_timestamp=10,
                             transactions=[],
                             miner_address=alice_xmss.address)
        mining_blob = block.mining_blob
        self.assertTrue(block.blockheader.verify_blob(mining_blob))

    def test_mining_blob(self):
        alice_xmss = get_alice_xmss()
        block = Block.create(block_number=5,
                             prev_headerhash=bytes(sha2_256(b'test')),
                             prev_timestamp=10,
                             transactions=[],
                             miner_address=alice_xmss.address)

        block.set_nonces(mining_nonce=5, extra_nonce=4)

        mining_blob = block.mining_blob
        self.assertEqual(len(mining_blob), config.dev.mining_blob_size)
        mining_nonce_bytes = mining_blob[config.dev.mining_nonce_offset:config.dev.mining_nonce_offset + 4]
        extra_nonce_bytes = mining_blob[config.dev.extra_nonce_offset:config.dev.extra_nonce_offset + 8]

        mining_nonce = int.from_bytes(mining_nonce_bytes, byteorder='big', signed=False)
        extra_nonce = int.from_bytes(extra_nonce_bytes, byteorder='big', signed=False)

        self.assertEqual(mining_nonce, 5)
        self.assertEqual(extra_nonce, 4)

    def test_set_mining_nonce_from_blob(self):
        alice_xmss = get_alice_xmss()
        block = Block.create(block_number=5,
                             prev_headerhash=bytes(sha2_256(b'test')),
                             prev_timestamp=10,
                             transactions=[],
                             miner_address=alice_xmss.address)
        current_mining_nonce = block.mining_nonce
        current_headerhash = block.headerhash
        mining_blob = block.mining_blob
        block.blockheader.set_mining_nonce_from_blob(mining_blob)
        self.assertEqual(block.blockheader.mining_nonce, current_mining_nonce)
        self.assertEqual(block.headerhash, current_headerhash)
        self.assertEqual(block.blockheader.mining_blob, mining_blob)

    def test_update_mining_address(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()
        block = Block.create(block_number=5,
                             prev_headerhash=bytes(sha2_256(b'test')),
                             prev_timestamp=10,
                             transactions=[],
                             miner_address=alice_xmss.address)
        block.update_mining_address(mining_address=bob_xmss.address)
        coinbase_tx = Transaction.from_pbdata(block.transactions[0])
        self.assertTrue(isinstance(coinbase_tx, CoinBase))
        self.assertEqual(coinbase_tx.addr_to, bob_xmss.address)
        hashedtransactions = []
        for tx in block.transactions:
            hashedtransactions.append(tx.transaction_hash)
        self.assertEqual(block.blockheader.tx_merkle_root, merkle_tx_hash(hashedtransactions))
