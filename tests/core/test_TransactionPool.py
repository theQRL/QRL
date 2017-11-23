# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.TransactionPool import TransactionPool

logger.initialize_default(force_console_output=True)


class TestTransactionPool(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestTransactionPool, self).__init__(*args, **kwargs)

    def test_create(self):
        tp = TransactionPool()
        self.assertIsNotNone(tp)

    # TODO: Check what is obsolete and add tests
