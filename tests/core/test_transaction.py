from unittest import TestCase
from qrl.core import logger
from qrl.crypto.xmss import XMSS
from qrl.core.Transaction import SimpleTransaction, StakeTransaction

logger.initialize_default(force_console_output=True)


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

    def test_create_no_negative_amounts(self):
        # Alice sending a negative amount to Bob
        result = self.tx.create(self.alice.get_address(), self.bob.get_address(), -10, 1, self.alice.pk(),
                                self.alice.get_index())

        # In the old code, this would return a False.
        # Currently validation is broken.
        # Not sure what future code will do, but it should also fail somewhere.

        self.assertFalse(result)

    def test_validate_tx(self):
        # If we change amount, fee, txfrom, txto, (maybe include xmss stuff) txhash should change.
        tx = self.tx.create(self.alice.get_address(), self.bob.get_address(), 100, 1, self.alice.pk(),
                                    self.alice.get_index())

        # We must sign the tx before validation will work.
        tx.sign(alice)

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

    def test_create(self):
        tx = self.stake_tx.create(2, self.alice, self.alice.pk(), balance=100)
        self.assertTrue(tx)

    def test_validate_tx(self):
        tx = self.stake_tx.create(2, self.alice, self.alice.pk(), balance=100)

        # We must sign the tx before validation will work.
        tx.sign(alice)

        # We haven't touched the tx: validation should pass
        self.assertTrue(tx.validate_tx())