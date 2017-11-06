# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import pytest

from qrl.core import logger
from qrl.core.Chain import Chain
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State

logger.initialize_default(force_console_output=True)


class TestGenesisBlock(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestGenesisBlock, self).__init__(*args, **kwargs)

    def test_genesis_block_values(self):
        gb = GenesisBlock()
        self.assertIsNotNone(gb)

        pass
