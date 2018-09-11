import json
from unittest import TestCase

from qrl.daemon.helper.DaemonHelper import Wallet, WalletEncryptionError
from tests.misc.helper import set_qrl_dir


class TestDaemonHelper(TestCase):
    def setUp(self):
        pass

    def test_open_wallet_with_slave_groups(self):
        with set_qrl_dir('wallet_ver1_walletd_slaves'):
            w = Wallet()
            self.assertEqual(len(w.address_items[0].slaves), 1)  # Main address has 1 slave group
            self.assertEqual(len(w.address_items[0].slaves[0]), 3)  # Slave group has 3 slaves

    def test_save_wallet_with_slave_groups(self):
        with set_qrl_dir('wallet_ver1_walletd_slaves'):
            w = Wallet()
            w.save()

    def test_encrypt_decrypt_wallet_with_slave_groups(self):
        with set_qrl_dir('wallet_ver1_walletd_slaves'):
            w1 = Wallet()
            w1.encrypt('test1234')
            w1.save()
            with open(w1.wallet_path) as f:
                wallet_encrypted = json.load(f)
                self.assertEqual(wallet_encrypted['encrypted'], True)

            w2 = Wallet()
            w2.decrypt('test1234')
            w2.save()
            with open(w1.wallet_path) as f:
                wallet_decrypted = json.load(f)
                self.assertEqual(wallet_decrypted['encrypted'], False)

    def test_set_slave_ots_index(self):
        with set_qrl_dir('wallet_ver1_walletd_slaves'):
            w1 = Wallet()

            # An AddressItem's data may be out of sync of the XMSS tree's data. Have to be careful when manipulating it.
            # At the same time, making AddressItem use properties everywhere is difficult....
            slave = w1.address_items[0].slaves[0][2]
            slave.generate_xmss()
            w1.set_slave_ots_index(0, 0, 2, 35)
            self.assertEqual(w1.address_items[0].slaves[0][2].index, 35)
            self.assertEqual(w1.address_items[0].slaves[0][2].xmss.ots_index, 35)

    def test_add_slave_group_unencrypted(self):
        with set_qrl_dir('wallet_ver1_walletd_slaves'):
            w1 = Wallet()
            w1.add_slave(0, 6, 5)
            example_slave_address = w1.address_items[0].slaves[0][1].qaddress
            w1.save()

            w2 = Wallet()
            self.assertEqual(w2.address_items[0].slaves[0][1].qaddress, example_slave_address)

    def test_add_slave_group_encrypted(self):
        with set_qrl_dir('wallet_ver1_walletd_slaves'):
            w1 = Wallet()
            w1.encrypt('test1234')
            with self.assertRaises(WalletEncryptionError):
                w1.add_slave(0, 6, 5)
            w1.decrypt('test1234')
            w1.add_slave(0, 6, 5)
            example_slave_address = w1.address_items[0].slaves[0][1].qaddress
            w1.encrypt('test1234')
            w1.save()

            w2 = Wallet()
            self.assertEqual(w2.address_items[0].slaves[0][1].qaddress, example_slave_address)
            self.assertEqual(w2.encrypted, True)
