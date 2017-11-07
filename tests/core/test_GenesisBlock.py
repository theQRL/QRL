# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.GenesisBlock import GenesisBlock

logger.initialize_default(force_console_output=True)


class TestGenesisBlock(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestGenesisBlock, self).__init__(*args, **kwargs)

    def test_genesis_block_values(self):
        gb = GenesisBlock()

        self.assertIsNotNone(gb)
        self.assertEqual(0, gb.block_number)
        self.assertEqual(b'QuantumBoosterTestnet', gb.prev_headerhash)
        self.assertEqual(6, len(gb.genesis_balance))
