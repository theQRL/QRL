# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from timeout_decorator import timeout_decorator

from qrlcore import logger
from qrlcore.chain import Chain
from qrlcore.state import State

logger.initialize_default(force_console_output=True)

class TestChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChain, self).__init__(*args, **kwargs)

    @timeout_decorator.timeout(5)
    def test_create_chain(self):
        state = State()
        self.assertIsNotNone(state)

        chain = Chain(state)
        self.assertIsNotNone(chain)
