# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import sha2_256, bin2hstr

from qrl.core.Wallet import Wallet
from tests.misc.helper import get_alice_xmss, set_wallet_dir
from qrl.core.misc import logger
from qrl.core.Block import Block

logger.initialize_default()


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    def test_init(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet(valid_or_create=False)
            self.assertIsNotNone(wallet)

    def test_read(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet(valid_or_create=False)
            self.assertEqual(1, len(wallet.addresses))

            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(wallet.addresses[0]))
