# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.BlockHeader import BlockHeader

logger.initialize_default(force_console_output=True)


class TestBlockHeader(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBlockHeader, self).__init__(*args, **kwargs)

    def test_init(self):
        # TODO: Not much going on here..
        block_header = BlockHeader()
        self.assertIsNotNone(block_header)  # just to avoid warnings
