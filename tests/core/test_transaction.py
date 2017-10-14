from unittest import TestCase
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
    'pubhash': '1234',
    'txhash': '1234',
    # >> Signature components
    'signature': 'abc12341',
    'PK': '1234',
    ############## Specific content
    'txto': '1234',
    'amount': '1234',
    'fee': '1234',
}

test_txdict_Stake = {
    'subtype': TX_SUBTYPE_STAKE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    # >> Signature components
    'signature': 'abc12341',
    'PK': '1234',
    ############## Specific content
    'epoch': 1,
    'balance': 1,
    'slave_public_key' : '1234',
    'hash': '1234',
    'first_hash': '1234',
}

test_txdict_CoinBase = {
    'subtype': TX_SUBTYPE_COINBASE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    # >> Signature components
    'signature': 'abc12341',
    'PK': '1234',
    ############## Specific content
    'txto': '1234',
    'amount': '1234',
}

test_txdict_Lattice = {
    'subtype': TX_SUBTYPE_LATTICE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    # >> Signature components
    'signature': 'abc12341',
    'PK': '1234',
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
        self.assertEqual(tx.txfrom, '1234')
        self.assertEqual(tx.pubhash, tuple('1234'))
        self.assertEqual(tx.txhash, tuple('1234'))

        # Test that signature components were copied over.
        self.assertEqual(tx.signature, tuple('abc12341'))
        self.assertEqual(tx.PK, tuple('1234'))

        # Test that specific content was copied over.
        self.assertEqual(tx.txto, '1234')
        self.assertEqual(tx.amount, 1234)
        self.assertEqual(tx.fee, 1234)

    def disabled_test_create_no_negative_amounts(self):
        # Alice sending a negative amount to Bob
        result = self.tx.create(self.alice.get_address(), self.bob.get_address(), -10, 1, self.alice.pk(),
                                self.alice.get_index())

        # In the old code, this would return a False.
        # Currently validation is broken.
        # Not sure what future code will do, but it should also fail somewhere.

        self.assertFalse(result)

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
        tx = self.stake_tx.create(2, self.alice, self.bob.pk(), balance=100)
        self.assertTrue(tx)

    def test_from_txdict(self):
        tx = Transaction.from_txdict(test_txdict_Stake)
        self.assertIsInstance(tx, StakeTransaction)

        # Test that common Transaction components were copied over.
        self.assertEqual(tx.ots_key, 1)
        self.assertEqual(tx.nonce, 1)
        self.assertEqual(tx.txfrom, '1234')
        self.assertEqual(tx.pubhash, tuple('1234'))
        self.assertEqual(tx.txhash, tuple('1234'))

        # Test that signature components were copied over.
        self.assertEqual(tx.signature, tuple('abc12341'))
        self.assertEqual(tx.PK, tuple('1234'))

        # Test that specific content was copied over.
        self.assertEqual(tx.epoch, 1)
        self.assertEqual(tx.balance, 1)
        self.assertEqual(tx.slave_public_key, tuple('1234'))
        self.assertEqual(tx.hash, [('1',), ('2',), ('3',), ('4',)])
        self.assertEqual(tx.first_hash, tuple('1234'))

    def disabled_test_validate_tx(self):
        tx = self.stake_tx.create(2, self.alice, self.bob.pk(), balance=100)

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We haven't touched the tx: validation should pass
        self.assertTrue(tx.validate_tx())

    def test_get_message_hash(self):
        tx = self.stake_tx.create(0, self.alice, self.alice.pk(), None, first_hash=self.alice.pk(), balance=10)

        # Currently, a Transaction's message is always blank (what is it used for?)
        answer = (122, 232, 174, 53, 1, 13, 82, 121, 232, 68, 239, 224, 231, 164, 227, 197, 180, 44, 69, 225, 244, 158, 145, 27, 172, 243, 250, 215, 64, 196, 233, 182)
        self.assertEqual(tx.get_message_hash(), answer)


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
        self.assertEqual(tx.txfrom, '1234')
        self.assertEqual(tx.pubhash, tuple('1234'))
        self.assertEqual(tx.txhash, tuple('1234'))

        # Test that signature components were copied over.
        self.assertEqual(tx.signature, tuple('abc12341'))
        self.assertEqual(tx.PK, tuple('1234'))

        # Test that specific content was copied over.
        self.assertEqual(tx.txto, '1234')
        self.assertEqual(tx.amount, 1234)
