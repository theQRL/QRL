# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.Block import Block

logger.initialize_default(force_console_output=True)


class TestBlock(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBlock, self).__init__(*args, **kwargs)

    def test_init(self):
        # TODO: Not much going on here..
        block = Block()
        self.assertIsNotNone(block)             # just to avoid warnings
