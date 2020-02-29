# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from decimal import Decimal
from unittest import TestCase

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.formulas import calc_coeff, remaining_emission

logger.initialize_default()


class TestFormulas(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestFormulas, self).__init__(*args, **kwargs)

    def test_calc_coeff(self):
        self.assertEqual(calc_coeff(config.dev), Decimal('1.664087503734056374552843909E-7'))
        # TODO: Test more values

    def test_remaining_emission(self):
        logger.info(remaining_emission(100, config.dev))
        self.assertEqual(remaining_emission(100, config.dev), Decimal('39999334370536850'))
        # TODO: Test more values
