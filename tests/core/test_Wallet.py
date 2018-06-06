# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import bin2hstr

from qrl.core.Wallet import Wallet, WalletEncryptionError, WalletVersionError, WalletDecryptionError
from qrl.core.misc import logger
from tests.misc.helper import set_qrl_dir

logger.initialize_default()


class TestWalletVer0(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWalletVer0, self).__init__(*args, **kwargs)

    def test_init(self):
        with set_qrl_dir("wallet_ver0"):
            wallet = Wallet()
            self.assertIsNotNone(wallet)

    def test_read_ver0(self):
        with set_qrl_dir("wallet_ver0"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 0)

            addr_item = wallet.address_items[0]
            self.assertFalse(addr_item.encrypted)

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_read_secure_ver0(self):
        with set_qrl_dir("wallet_secure_ver0"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 0)

            self.assertTrue(wallet.address_items[0].encrypted)

            wallet.decrypt_item_ver0(0, 'test1234')
            addr_item = wallet.address_items[0]

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_read_wallet_ver0_saves_wallet_ver1(self):
        with set_qrl_dir("wallet_ver0"):
            wallet = Wallet()
            self.assertEqual(wallet.version, 0)

            wallet.version = 1
            wallet.save()

            wallet_reloaded = Wallet()
            self.assertEqual(wallet_reloaded.version, 1)

    def test_read_wallet_secure_ver0_saves_wallet_ver1_encrypted(self):
        with set_qrl_dir("wallet_secure_ver0"):
            wallet = Wallet()

            self.assertEqual(wallet.version, 0)

            # Wallet will not let you save an encrypted ver0 wallet as ver1. You have to decrypt it first.
            # This is because Qaddress is unencrypted in the ver1 wallet.
            with self.assertRaises(WalletVersionError):
                wallet.save()

            wallet.decrypt('test1234')
            wallet.encrypt('test1234')
            wallet.version = 1
            wallet.save()

            wallet_reloaded = Wallet()
            self.assertEqual(wallet_reloaded.version, 1)

            self.assertEqual(wallet_reloaded.address_items[0].qaddress,
                             'Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f')

            wallet_reloaded.decrypt('test1234')
            addr_item = wallet_reloaded.address_items[0]

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet_reloaded.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet_reloaded.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))


class TestWallet(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestWallet, self).__init__(*args, **kwargs)

    def test_read(self):
        with set_qrl_dir("wallet_ver1"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 1)

            addr_item = wallet.address_items[0]
            self.assertFalse(addr_item.encrypted)

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_read_secure(self):
        with set_qrl_dir("wallet_secure_ver1"):
            wallet = Wallet()
            self.assertEqual(1, len(wallet.address_items))
            self.assertEqual(wallet.version, 1)
            self.assertTrue(wallet.encrypted)

            addr_item = wallet.address_items[0]

            self.assertEqual('Q010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             addr_item.qaddress)

            wallet.decrypt_item(0, 'test1234')
            xmss0 = wallet.get_xmss_by_index(0)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0.address))

            xmss0b = wallet.get_xmss_by_address(xmss0.address)
            self.assertEqual('010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f',
                             bin2hstr(xmss0b.address))

    def test_create(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            self.assertEqual(0, len(wallet.address_items))

            xmss1 = wallet.add_new_address(4)
            self.assertEqual(1, len(wallet.address_items))

            xmss2 = wallet.get_xmss_by_index(0)

            self.assertEqual(xmss1.address, xmss2.address)
            self.assertEqual(xmss1.mnemonic, xmss2.mnemonic)

    def test_create_load(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.save()

            wallet_b = Wallet()
            self.assertEqual(1, len(wallet_b.address_items))

            self.assertEqual(wallet.address_items[0], wallet_b.address_items[0])

    def test_create_custom_hash_function(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            xmss = wallet.add_new_address(height=4, hash_function="sha2_256")
            self.assertEqual("sha2_256", xmss.hash_function)

    def test_create_custom_hash_function_load(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            xmss = wallet.add_new_address(height=4, hash_function="sha2_256")
            wallet.save()

            self.assertEqual("sha2_256", xmss.hash_function)

            wallet_reloaded = Wallet()
            self.assertEqual("sha2_256", wallet_reloaded.address_items[0].hashFunction)

    def test_integrity_behaviour(self):
        with set_qrl_dir("no_data"):
            TEST_KEY = 'mytestkey'
            wallet = Wallet()
            wallet.add_new_address(4)
            wallet.add_new_address(4)
            wallet.encrypt(TEST_KEY)

            # An encrypted wallet is not editable.
            with self.assertRaises(WalletEncryptionError):
                wallet.add_new_address(4)
            # You may not re-encrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.encrypt(TEST_KEY)
            # You can save it.
            wallet.save()

            wallet.decrypt_item(1, TEST_KEY)
            # A partially encrypted wallet is not editable.
            with self.assertRaises(WalletEncryptionError):
                wallet.add_new_address(4)
            # You may not re-encrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.encrypt(TEST_KEY)
            # You may not re-decrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.decrypt(TEST_KEY)
            # You can't even save it.
            with self.assertRaises(WalletEncryptionError):
                wallet.save()

            wallet.decrypt_item(0, TEST_KEY)
            # A fully decrypted wallet is editable.
            wallet.add_new_address(4)
            # You may not re-decrypt it.
            with self.assertRaises(WalletEncryptionError):
                wallet.decrypt(TEST_KEY)
            # You can save it.
            wallet.save()

    def test_encrypt_wallet(self):
        # 2 unencrypted addresses. This should work.
        with set_qrl_dir("no_data"):
            TEST_KEY = 'mytestkey'
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.add_new_address(height=4)

            wallet.encrypt(TEST_KEY)

            self.assertTrue(wallet.encrypted)
            self.assertFalse(wallet.encrypted_partially)

    def test_decrypt_wallet(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.add_new_address(height=4)
            addresses = wallet.addresses

            TEST_KEY = 'mytestkey'
            wallet.encrypt(TEST_KEY)
            self.assertTrue(wallet.encrypted)

            wallet.decrypt(TEST_KEY)
            self.assertEqual(addresses, wallet.addresses)
            self.assertFalse(wallet.encrypted_partially)

    def test_decrypt_wallet_wrong(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.add_new_address(height=4)
            addresses = wallet.addresses

            TEST_KEY = 'mytestkey'
            wallet.encrypt(TEST_KEY)
            self.assertTrue(wallet.encrypted)

            TEST_KEY = 'mytestkey_is_wrong'
            with self.assertRaises(WalletDecryptionError):
                wallet.decrypt(TEST_KEY)
            self.assertEqual(addresses, wallet.addresses)
            self.assertFalse(wallet.encrypted_partially)

    def test_encrypt_save_reload(self):
        with set_qrl_dir("no_data"):
            wallet = Wallet()
            wallet.add_new_address(height=4)
            wallet.save()

            wallet_b = Wallet()

            self.assertEqual(1, len(wallet_b.address_items))
            self.assertEqual(wallet.address_items[0], wallet_b.address_items[0])

            TEST_KEY = 'mytestkey'

            wallet_b.encrypt(TEST_KEY)
            wallet_b.save()

            self.assertEqual(1, len(wallet_b.address_items))
            self.assertNotEqual(wallet.address_items[0], wallet_b.address_items[0])

            wallet_c = Wallet()
            self.assertEqual(1, len(wallet_c.address_items))
            self.assertTrue(wallet_c.address_items[0].encrypted)

            wallet_c.decrypt(TEST_KEY)
            self.assertFalse(wallet_c.address_items[0].encrypted)
            self.assertEqual(wallet.address_items[0], wallet_c.address_items[0])
