# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.GenesisBlock import GenesisBlock
from tests.misc.helper import clean_genesis

logger.initialize_default()


class TestGenesisBlock(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestGenesisBlock, self).__init__(*args, **kwargs)

    def test_genesis_block_values(self):
        with clean_genesis():
            gb = GenesisBlock()

            self.assertIsNotNone(gb)
            self.assertEqual(0, gb.block_number)

            self.assertEqual(config.user.genesis_prev_headerhash, gb.prev_headerhash)
            self.assertEqual(1, len(gb.genesis_balance))
