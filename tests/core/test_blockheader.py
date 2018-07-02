# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import mock, Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.BlockHeader import BlockHeader
from qrl.crypto.misc import sha256

logger.initialize_default()


@mock.patch('qrl.core.misc.ntp.getTime', return_value=1615270948)
class TestBlockHeader(TestCase):
    def setUp(self):
        with mock.patch('qrl.core.misc.ntp.getTime', return_value=1615270948) as time_mock:
            self.block_header = BlockHeader.create(1, sha256(b'prev'), time_mock.return_value, sha256(b'txs'), 10)

        self.fee_reward = 10
        self.coinbase_amount = self.block_header.block_reward + self.fee_reward

        # this variable is for validate_parent_child_relation()
        self.m_parent_block = Mock(
            name='mock Parent Block',
            block_number=self.block_header.block_number - 1,
            headerhash=self.block_header.prev_headerhash,
            timestamp=self.block_header.timestamp - 1
        )

    def test_create(self, time_mock):
        b = BlockHeader.create(blocknumber=1, prev_headerhash=b'headerhash', prev_timestamp=10,
                               hashedtransactions=b'some_data', fee_reward=1)
        self.assertIsNotNone(b)

        b = BlockHeader.create(blocknumber=1, prev_headerhash=b'headerhash', prev_timestamp=10,
                               hashedtransactions=b'some_data', fee_reward=1)
        self.assertEqual(b.epoch, 0)

    def test_create_fails_when_prev_timestamp_is_negative(self, time_mock):
        # The only way to get it to fail in this mode is to pass a negative timestamp. Which should never happen IRL.
        time_mock.return_value = 0
        b = BlockHeader.create(1, sha256(b'prev'), -10, sha256(b'txs'), 10)
        self.assertIsNone(b)

    def test_create_uses_prev_timestamp_when_genesis_block(self, time_mock):
        genesis = BlockHeader.create(0, sha256(b'Random Scifi Book Title'), time_mock.return_value, sha256(b'txs'), 10)
        self.assertEqual(genesis.timestamp, time_mock.return_value)

    def test_block_reward_calc_genesis_is_total_coin_supply(self, time_mock):
        genesis = BlockHeader.create(0, sha256(b'Random Scifi Book Title'), time_mock.return_value, sha256(b'txs'), 10)
        self.assertEqual(config.dev.supplied_coins, genesis.block_reward)

    def test_init(self, time_mock):
        block_header = BlockHeader()
        self.assertIsNotNone(block_header)  # just to avoid warnings

    def test_init2(self, time_mock):
        self.assertIsNotNone(self.block_header)  # just to avoid warnings

    def test_blob(self, time_mock):
        self.assertEquals('00501846b24200c31fca7172a7f701ae50322579cfdf1d7777daab4ce6ead70b76debb2c51a1'
                          'c700000000000000000000000000000000002b80aecec05ad5c7c4f2259c8f69e2966a6ce102',
                          bin2hstr(self.block_header.mining_blob))
        self.assertEquals(config.dev.mining_blob_size, len(self.block_header.mining_blob))

    def test_hash(self, time_mock):
        header_hash = self.block_header.generate_headerhash()

        self.assertEquals('ac021e63df860ea930ea9de05e350d3f74af35341688134f92957f1dac3a62fb', bin2hstr(header_hash))

        self.assertEquals(bin2hstr(header_hash), bin2hstr(self.block_header.headerhash))

        self.assertEquals(32, len(self.block_header.headerhash))

    def test_hash_nonce(self, time_mock):
        self.block_header.set_nonces(100, 0)

        header_hash = self.block_header.generate_headerhash()

        self.assertEquals('b6f937020f9876f3c6887e7a6759201411ed8826ed9ce4283ffe48e1aa90d692',
                          bin2hstr(header_hash))

        self.assertEquals(bin2hstr(header_hash),
                          bin2hstr(self.block_header.headerhash))

        self.assertEquals(32, len(self.block_header.headerhash))

    def test_validate_pass(self, time_mock):
        result = self.block_header.validate(self.fee_reward, self.coinbase_amount, self.block_header.tx_merkle_root)
        self.assertTrue(result)

    def test_validate_fail_timestamp_checks(self, time_mock):
        # The Block's timestamp is too far in the future
        time_mock.return_value = 10  # set our current_time way backwards
        result = self.block_header.validate(self.fee_reward, self.coinbase_amount, self.block_header.tx_merkle_root)
        self.assertFalse(result)
        time_mock.return_value = 1615270948

        # Block came out before Genesis block?!
        self.block_header._data.timestamp_seconds = 0
        result = self.block_header.validate(self.fee_reward, self.coinbase_amount, self.block_header.tx_merkle_root)
        self.assertFalse(result)
        self.block_header._data.timestamp_seconds = 1615270948

    def test_validate_fail_headerhash(self, time_mock):
        # BlockHeader recalculates the headerhash. If the recalculation is different...
        with mock.patch('qrl.core.BlockHeader.BlockHeader.generate_headerhash', return_value=b'nonsense'):
            result = self.block_header.validate(self.fee_reward, self.coinbase_amount, self.block_header.tx_merkle_root)
            self.assertFalse(result)

    def test_validate_fail_rewards_and_wrong_merkleroot(self, time_mock):
        # Recalculates the expected block_reward for this block_number. If the recalculation is different...
        with mock.patch('qrl.core.BlockHeader.BlockHeader.block_reward_calc', return_value=0):
            result = self.block_header.validate(self.fee_reward, self.coinbase_amount, self.block_header.tx_merkle_root)
            self.assertFalse(result)

        # The function above says that the fee_reward should be 3, but the BlockHeader thought it was 10
        result = self.block_header.validate(3, self.block_header.block_reward + 3, self.block_header.tx_merkle_root)
        self.assertFalse(result)

        # coinbase_amount should be BlockHeader.block_reward + BlockHeader.fee_reward
        result = self.block_header.validate(self.fee_reward, self.block_header.block_reward + 5,
                                            self.block_header.tx_merkle_root)
        self.assertFalse(result)

        # The function above says that the Merkle root should be something else
        result = self.block_header.validate(self.fee_reward, self.coinbase_amount, b'some other merkle root')
        self.assertFalse(result)

    def test_validate_parent_child_relation(self, time_mock):
        # Verifies that a Block is the parent of this Block.
        # If we pass it a None, it should return False.
        result = self.block_header.validate_parent_child_relation(None)
        self.assertFalse(result)

    def test_validate_parent_child_relation_pass(self, time_mock):
        result = self.block_header.validate_parent_child_relation(self.m_parent_block)
        self.assertTrue(result)

    def test_validate_parent_child_relation_parent_block_number_must_be_smaller_by_1(self, time_mock):
        # The Parent Block.block_number must be smaller by 1
        self.m_parent_block.block_number = self.block_header.block_number - 2
        result = self.block_header.validate_parent_child_relation(self.m_parent_block)
        self.assertFalse(result)

    def test_validate_parent_child_relation_parent_headerhash_is_prev_headerhash(self, time_mock):
        # The Parent Block's headerhash must be the BlockHeader.prev_headerhash
        self.m_parent_block.headerhash = b'something else totally'
        result = self.block_header.validate_parent_child_relation(self.m_parent_block)
        self.assertFalse(result)

    def test_validate_parent_child_relation_parent_block_must_be_older(self, time_mock):
        self.m_parent_block.timestamp = self.block_header.timestamp + 10
        result = self.block_header.validate_parent_child_relation(self.m_parent_block)
        self.assertFalse(result)

    def test_verify_blob(self, time_mock):
        # verify_blob() ensures the miner did not tamper with anything other than the mining nonce.
        blob = bytearray(self.block_header.mining_blob)
        # if we meddle with the bytes between mining_nonce_offset and mining_nonce_offset + 17, the blob should pass
        for i in range(config.dev.mining_nonce_offset, config.dev.mining_nonce_offset + 17):
            blob[i] = 6
        # it should still pass verification
        result = self.block_header.verify_blob(blob)
        self.assertTrue(result)

        # But if we change the bits outside of this range, verification will fail.
        blob[56] = 6
        result = self.block_header.verify_blob(blob)
        self.assertFalse(result)

    def test_update_merkle_root(self, time_mock):
        # update_merkle_root() changes the BlockHeader's merkle root,
        # calls set_nonces() to reset the nonces to 0 and
        # recalculates the blockhash.
        self.block_header.set_nonces(1, 1)
        old_hash = self.block_header.headerhash

        self.block_header.update_merkle_root(b'new merkle root')

        self.assertEqual(self.block_header.mining_nonce, 0)
        self.assertEqual(self.block_header.extra_nonce, 0)
        self.assertNotEqual(old_hash, self.block_header.headerhash)

    def test_set_mining_nonce_from_blob(self, time_mock):
        # set_mining_nonce_from_blob() takes a binary blob and just copies the nonce, extranonce over.
        # See BlockHeader.mining_blob for construction details. nonce + extranonce + padding = 4 + 8 + 5
        mock_blob = bytearray(100)
        # nonce
        for i in range(config.dev.mining_nonce_offset, config.dev.mining_nonce_offset + 4):
            mock_blob[i] = 1
        # extranonce
        for i in range(config.dev.extra_nonce_offset, config.dev.extra_nonce_offset + 8):
            mock_blob[i] = 2
        # 5 bytes padding, for pool use apparently
        for i in range(config.dev.extra_nonce_offset + 8, config.dev.extra_nonce_offset + 14):
            mock_blob[i] = 3

        self.block_header.set_mining_nonce_from_blob(mock_blob)

        self.assertEqual(self.block_header.mining_nonce, 16843009)
        self.assertEqual(self.block_header.extra_nonce, 144680345676153346)
