# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
from os.path import isfile
from unittest import TestCase

from pyqrllib.pyqrllib import hstr2bin

from qrl.core import logger, config
from qrl.core.Wallet import Wallet
from tests.misc.helper import set_wallet_dir

logger.initialize_default(force_console_output=True)


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    def test_create_wallet(self):
        with set_wallet_dir("no_wallet"):
            wallet = Wallet()
            self.assertIsNotNone(wallet)
            wallet_file_path = os.path.join(config.user.wallet_path, "wallet.qrl")
            self.assertTrue(isfile(wallet_file_path))

    def test_getnewaddress(self):
        with set_wallet_dir("test_wallet"):
            wallet = Wallet()
            S1 = hstr2bin(
                '7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4')
            address = wallet.get_new_address(seed=S1)
            self.assertIsNotNone(address.address)
            self.assertEqual(b'Q56e5d6410a5716e548d89ca27b8f057122af9560ba3cd8aa99879f32758330267811af83',
                             address.address)
