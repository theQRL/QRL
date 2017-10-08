# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.walletfactory import WalletFactory
from qrl.core.walletprotocol import WalletProtocol

logger.initialize_default(force_console_output=True)


class TestWalletFactory(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWalletFactory, self).__init__(*args, **kwargs)

    def test_create_factory(self):
        factory = WalletFactory(stuff=None,
                                chain=None,
                                state=None,
                                p2pFactory=None,
                                api_factory=None,
                                qrlnode=None)

        self.assertEqual(factory.protocol, WalletProtocol,
                         "Factory has not been assigned the expected protocol")
