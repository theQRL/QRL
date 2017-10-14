from unittest import TestCase

from pytest import raises

from qrl.core import logger
from qrl.crypto.xmss import XMSS
from qrl.core.Transaction import Transaction, SimpleTransaction, StakeTransaction, CoinBase
from qrl.core.Transaction_subtypes import *

logger.initialize_default(force_console_output=True)

test_txdict_Simple = {
    'subtype': TX_SUBTYPE_TX,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': b'1234',
    'txhash': b'1234',
    # >> Signature components
    'signature': b'abc12341',
    'PK': b'1234',
    ############## Specific content
    'txto': '1234',
    'amount': 1234,
    'fee': 1234,
}

test_txdict_Stake = {
    'subtype': TX_SUBTYPE_STAKE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': b'1234',
    'txhash': b'1234',
    # >> Signature components
    'signature': b'abc12341',
    'PK': b'1234',
    ############## Specific content
    'epoch': 1,
    'finalized_blocknumber': 25,
    'finalized_headerhash': b'1234',
    'balance': 1,
    'slave_public_key' : b'1234',
    'hash': b'1234',
    'first_hash': b'1234',
}

test_txdict_CoinBase = {
    'subtype': TX_SUBTYPE_COINBASE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': b'1234',
    'txhash': b'1234',
    # >> Signature components
    'signature': b'abc12341',
    'PK': b'1234',
    ############## Specific content
    'txto': '1234',
    'amount': '1234',
}

test_txdict_Lattice = {
    'subtype': TX_SUBTYPE_LATTICE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': b'1234',
    'pubhash': b'1234',
    'txhash': b'1234',
    # >> Signature components
    'signature': b'abc12341',
    'PK': b'1234',
    ############## Specific content
}

wrap_message_expected1 = bytearray(b'\xff\x00\x0000000027\x00{"data": 12345, "type": "TESTKEY_1234"}\x00\x00\xff')
wrap_message_expected1b = bytearray(b'\xff\x00\x0000000027\x00{"type": "TESTKEY_1234", "data": 12345}\x00\x00\xff')


class TestSimpleTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSimpleTransaction, self).__init__(*args, **kwargs)
        self.tx = SimpleTransaction()
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

    def test_create(self):
        # Alice sending coins to Bob
        result = self.tx.create(self.alice.get_address(), self.bob.get_address(), 100, 1, self.alice.pk(),
                                self.alice.get_index())
        self.assertTrue(result)

    def test_from_txdict(self):
        tx = Transaction.from_txdict(test_txdict_Simple)
        self.assertIsInstance(tx, SimpleTransaction)
        self.assertEqual(tx.subtype, TX_SUBTYPE_TX)

        # Test that common Transaction components were copied over.
        self.assertEqual(tx.ots_key, 1)
        self.assertEqual(tx.nonce, 1)
        self.assertEqual(b'1234', tx.txfrom)
        self.assertEqual(b'1234', tx.pubhash)
        self.assertEqual(b'1234', tx.txhash)

        # Test that signature components were copied over.
        self.assertEqual(b'abc12341', tx.signature)
        self.assertEqual(b'1234', tx.PK)

        # Test that specific content was copied over.
        self.assertEqual(b'1234', tx.txto, )
        self.assertEqual(1234, tx.amount)
        self.assertEqual(1234, tx.fee)

    def test_create_no_negative_amounts(self):
        # Alice sending a negative amount to Bob
        with self.assertRaises(ValueError):
            result = self.tx.create(self.alice.get_address(), self.bob.get_address(), -10, 1, self.alice.pk(),
                                    self.alice.get_index())

    def disabled_test_validate_tx(self):
        # If we change amount, fee, txfrom, txto, (maybe include xmss stuff) txhash should change.
        tx = self.tx.create(self.alice.get_address(), self.bob.get_address(), 100, 1, self.alice.pk(),
                                    self.alice.get_index())

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_tx())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass


class TestStakeTransaction(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestStakeTransaction, self).__init__(*args, **kwargs)
        self.stake_tx = StakeTransaction()
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

    def test_create(self):
        tx = self.stake_tx.create(2, self.alice, self.bob.pk(), 0, bytes([0, 1]), balance=100)
        self.assertTrue(tx)

    def test_from_txdict(self):
        tx = Transaction.from_txdict(test_txdict_Stake)
        self.assertIsInstance(tx, StakeTransaction)

        # Test that common Transaction components were copied over.
        self.assertEqual(1, tx.ots_key)
        self.assertEqual(1, tx.nonce)
        self.assertEqual(b'1234', tx.txfrom )
        self.assertEqual(b'1234', tx.pubhash )
        self.assertEqual(b'1234', tx.txhash)

        # Test that signature components were copied over.
        self.assertEqual(b'abc12341', tx.signature)
        self.assertEqual(b'1234', tx.PK)

        # Test that specific content was copied over.
        self.assertEqual(1, tx.epoch)
        self.assertEqual(25, tx.finalized_blocknumber)
        self.assertEqual(b'1234', tx.finalized_headerhash)
        self.assertEqual(1, tx.balance)
        self.assertEqual(b'1234', tx.slave_public_key)
        self.assertEqual([b'1', b'2', b'3', b'4'], tx.hash)
        self.assertEqual(b'1234', tx.first_hash)

    def disabled_test_validate_tx(self):
        tx = self.stake_tx.create(blocknumber=2,
                                  xmss=self.alice,
                                  slave_public_key=self.bob.pk(),
                                  finalized_blocknumber=5,
                                  finalized_headerhash='finalized_headerhash',
                                  balance=100)

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We haven't touched the tx: validation should pass
        self.assertTrue(tx.validate_tx())

    def test_get_message_hash(self):
        tx = self.stake_tx.create(blocknumber=0,
                                  xmss=self.alice,
                                  slave_public_key=self.alice.pk(),
                                  finalized_blocknumber=0,
                                  finalized_headerhash=b'some_headerhash',
                                  hashchain_terminator=None,
                                  first_hash=self.alice.pk(),
                                  balance=10)

        # Currently, a Transaction's message is always blank (what is it used for?)
        expected_answer = b'B&w\xb0\xd4v\xbd\xef9\xd4N\x06q\xe3\x9d\xd1I\x9c\x93\x9c\xa1;o\x96\x02\xb6\x13l\xda\x9cb/'
        self.assertEqual(expected_answer, tx.get_message_hash())


class TestCoinBase(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCoinBase, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.tx = CoinBase()

        class MockBlockHeader:
            pass
        self.mock_blockheader = MockBlockHeader()

    def test_create(self):
        self.mock_blockheader.stake_selector = self.alice.get_address()
        self.mock_blockheader.block_reward = 50
        self.mock_blockheader.fee_reward = 40
        self.mock_blockheader.prev_blockheaderhash = (0,1,2,3)
        self.mock_blockheader.blocknumber = 1
        self.mock_blockheader.headerhash = (1,2,3,4)

        tx = self.tx.create(self.mock_blockheader, self.alice)
        self.assertIsInstance(tx, CoinBase)

    def test_from_txdict(self):
        tx = Transaction.from_txdict(test_txdict_CoinBase)
        self.assertIsInstance(tx, CoinBase)

        # Test that common Transaction components were copied over.
        self.assertEqual(tx.ots_key, 1)
        self.assertEqual(tx.nonce, 1)
        self.assertEqual(b'1234', tx.txfrom)
        self.assertEqual(b'1234', tx.pubhash)
        self.assertEqual(b'1234', tx.txhash)

        # Test that signature components were copied over.
        self.assertEqual(b'abc12341', tx.signature)
        self.assertEqual(b'1234', tx.PK)

        # Test that specific content was copied over.
        self.assertEqual(b'1234', tx.txto)
        self.assertEqual(tx.amount, 1234)
