# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from timeout_decorator import timeout_decorator

from qrlcore import logger
from qrlcore.chain import Chain
from qrlcore.state import State
from qrlcore.wallet import Wallet

logger.initialize_default(force_console_output=True)


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    @timeout_decorator.timeout(1)
    def test_create_wallet(self):
        state = State()
        self.assertIsNotNone(state)

        chain = Chain(state)
        self.assertIsNotNone(state)

        wallet = Wallet(chain, state)
        self.assertIsNotNone(state)

    @timeout_decorator.timeout(1)
    def test_getnewaddress(self):
        wallet = Wallet(None, None)
        address = wallet.getnewaddress()
