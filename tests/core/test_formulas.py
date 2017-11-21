# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from decimal import Decimal
from unittest import TestCase

from qrl.core import logger
from qrl.core.formulas import calc_coeff, remaining_emission

logger.initialize_default(force_console_output=True)


class TestFormulas(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestFormulas, self).__init__(*args, **kwargs)

    def test_calc_coeff(self):
        # TODO: Verify value and required precision
        self.assertAlmostEqual(calc_coeff(100, 2), 2.302585092994046, places=10)
        # TODO: Test more values

    def test_remaining_emission(self):
        # TODO: Verify value and required precision
        print(remaining_emission(100, 2))
        self.assertEqual(remaining_emission(100, 2), Decimal('99.99999122'))
        # TODO: Test more values
