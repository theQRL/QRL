# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from binascii import unhexlify
from unittest import TestCase

from timeout_decorator import timeout_decorator

from qrlcore import logger
from qrlcore.chain import Chain
from qrlcore.state import State
from qrlcore.wallet import Wallet

logger.initialize_default(force_console_output=True)


class TestWallet(TestCase):
    S1 = unhexlify('7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4')

    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    # @timeout_decorator.timeout(1)
    # def test_create_wallet(self):
    #     state = State()
    #     self.assertIsNotNone(state)
    #
    #     chain = Chain(state)
    #     self.assertIsNotNone(state)
    #
    #     wallet = Wallet(chain, state)
    #     self.assertIsNotNone(state)
    #
    # @timeout_decorator.timeout(1)
    # def test_getnewaddress(self):
    #     wallet = Wallet(None, None)
    #     address = wallet.getnewaddress()

        chain = Chain(state)
        self.assertIsNotNone(state)

        wallet = Wallet(chain, state)
        self.assertIsNotNone(state)

    @timeout_decorator.timeout(100)
    def test_getnewaddress(self):
        wallet = Wallet(None, None)
        address = wallet.getnewaddress(SEED=TestWallet.S1)
        self.assertEqual(address[0], 'Q04402be77fb7df9c755883b066f1f33254a19d244c4dbae41b94f88a32b88a5921c7')
