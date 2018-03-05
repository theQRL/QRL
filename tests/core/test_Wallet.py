# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import bin2hstr

from qrl.core.Wallet import Wallet
from qrl.core.misc import logger
from tests.misc.helper import set_wallet_dir

logger.initialize_default()


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    def test_init(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet()
            self.assertIsNotNone(wallet)

    def test_read(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))

            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(wallet.address_items[0]))

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_create(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))

            xmss1 = wallet.add_new_address(4)
            self.assertEqual(2, len(wallet.address_items))

            xmss2 = wallet.get_xmss_by_index(1)

            self.assertEqual(xmss1.address, xmss2.address)
            self.assertEqual(xmss1.mnemonic, xmss2.mnemonic)

    def test_create_load(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet()
            wallet.add_new_address(4)

            wallet_2 = Wallet()
            self.assertEqual(2, len(wallet_2.address_items))

            self.assertEqual(wallet.address_items[0], wallet_2.address_items[0])
            self.assertEqual(wallet.address_items[1], wallet_2.address_items[1])
