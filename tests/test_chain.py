# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger

logger.initialize_default(force_console_output=True)


class TestChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChain, self).__init__(*args, **kwargs)

        # FIXME: Reenable this test
        # @timeout_decorator.timeout(5)
        # def test_create_chain(self):
        #     state = State()
        #     self.assertIsNotNone(state)
        #
        #     chain = Chain(state)
        #     self.assertIsNotNone(chain)
