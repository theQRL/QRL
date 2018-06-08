from unittest import TestCase

from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction

logger.initialize_default()


class TestTransaction(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestTransaction, self).__init__(*args, **kwargs)

    def test_calc_allowed_decimals(self):
        decimal = Transaction.calc_allowed_decimals(10000000000000000000)
        self.assertEqual(decimal, 0)

        decimal = Transaction.calc_allowed_decimals(1)
        self.assertEqual(decimal, 19)

        decimal = Transaction.calc_allowed_decimals(2)
        self.assertEqual(decimal, 18)
