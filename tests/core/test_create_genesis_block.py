# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.CreateGenesisBlock import CreateGenesisBlock

logger.initialize_default(force_console_output=True)


class TestChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChain, self).__init__(*args, **kwargs)

        def test_create_genesis_block(self):
            # FIXME: Creating a chain is untested
            # genesis_block = CreateGenesisBlock(chain)
            pass
