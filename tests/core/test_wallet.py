# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
import shutil
import tempfile
from shutil import copytree
from unittest import TestCase

import os

from os.path import isfile

import pytest
from pyqrllib.pyqrllib import hstr2bin

from qrl.core import logger, config
from qrl.core.wallet import Wallet

logger.initialize_default(force_console_output=True)


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    @contextlib.contextmanager
    def setWalletDir(self, wallet_name):
        dst_dir = tempfile.mkdtemp()
        try:
            test_path = os.path.dirname(os.path.abspath(__file__))
            src_dir = os.path.join(test_path, "..", "data", wallet_name)
            shutil.rmtree(dst_dir)
            copytree(src_dir, dst_dir)
            config.user.wallet_path = dst_dir
            yield
        finally:
            shutil.rmtree(dst_dir)

    def test_create_wallet(self):
        with self.setWalletDir("no_wallet"):
            wallet = Wallet()
            self.assertIsNotNone(wallet)
            wallet_file_path = os.path.join(config.user.wallet_path, "wallet.qrl")
            self.assertTrue(isfile( wallet_file_path ))

    @pytest.mark.skip(reason="old wallets are not supported anymore")
    def test_upgrade_wallet(self):
        with self.setWalletDir("old_wallet"):
            wallet_file_path = os.path.join(config.user.wallet_path, "wallet.qrl")
            self.assertFalse(isfile( wallet_file_path ))        # New wallet is NOT there

            wallet = Wallet()

            self.assertIsNotNone(wallet)
            self.assertTrue(isfile( wallet_file_path ))         # Now the new wallet appears

    def test_getnewaddress(self):
        with self.setWalletDir("test_wallet"):
            wallet = Wallet()
            S1 = hstr2bin('7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4')
            address = wallet.get_new_address(seed=S1)
            self.assertIsNotNone(address.address)
            self.assertEqual('Q56e5d6410a5716e548d89ca27b8f057122af9560ba3cd8aa99879f32758330267811af83', address.address)
