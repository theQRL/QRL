# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock
from pyqrllib.pyqrllib import bin2hstr, hstr2bin

from qrl.daemon.walletd import WalletD
from qrl.generated import qrl_pb2
from qrl.core.AddressState import AddressState
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.daemon.helper.DaemonHelper import WalletDecryptionError
from qrl.core.misc import logger
from tests.misc.helper import set_qrl_dir, get_alice_xmss, get_bob_xmss
from tests.misc.MockHelper.mock_function import MockFunction


logger.initialize_default()


class TestWalletD(TestCase):
    def __init__(self, *args, **kwargs):
        self.passphrase = '你好'
        self.qaddress = "Q010400ff39df1ba4d1d5b8753e6d04c51c34b95b01fc3650c10ca7b296a18bdc105412c59d0b3b"
        self.hex_seed = "0104008441d43524996f76236141d16b7b324323abf796e77ad" \
                        "7c874622a82f5744bb803f9b404d25733d0db82be7ac6f3c4cf"
        self.mnemonic = "absorb drank lute brick cure evil inept group grey " \
                        "breed hood reefy eager depict weed image law legacy " \
                        "jockey calm lover freeze fact lively wide dread spiral " \
                        "jaguar span rinse salty pulsar violet fare"
        super(TestWalletD, self).__init__(*args, **kwargs)

    def test_init(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            self.assertIsNotNone(walletd)

    def test_qaddress_to_address(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            qaddress = "Q010600968c3408cba5192d75c11cec909e803fc590e82463216b5a04ce8e447f76b4e02c0d3d81"
            address = walletd.qaddress_to_address(qaddress)
            self.assertEqual(qaddress[1:], bin2hstr(address))

    def test_authenticate(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd.authenticate()

            walletd._wallet = Mock()
            walletd._wallet.encrypted = Mock(return_value=True)
            with self.assertRaises(ValueError):
                walletd.authenticate()

    def test_get_unused_ots_index(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=10, unused_ots_index_found=True))

            qaddress = walletd.add_new_address_with_slaves(height=10)
            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            ots_index = walletd.get_unused_ots_index(walletd.qaddress_to_address(qaddress), 0)
            self.assertEqual(10, ots_index)

            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=10, unused_ots_index_found=False))

            ots_index = walletd.get_unused_ots_index(walletd.qaddress_to_address(qaddress), 0)
            self.assertIsNone(ots_index)

    def test_is_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))

            qaddress = walletd.add_new_address_with_slaves(height=10)
            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            self.assertTrue(walletd.is_slave(walletd.qaddress_to_address(qaddress), walletd.qaddress_to_address(qaddress)))

    def test_get_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            m = MockFunction()
            walletd.get_address_state = m.get

            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=10)
            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            master_addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            m.put(qaddress, master_addr_state)

            slaves = walletd.get_slave_list(qaddress)

            self.assertEqual(len(slaves), 1)
            self.assertEqual(len(slaves[0]), 3)

            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][1].pk)), 0)
            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][2].pk)), 0)
            slave00_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[0][0].qaddress))
            slave01_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[0][1].qaddress))
            slave02_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[0][2].qaddress))

            self.assertEqual(slaves[0][0].index, 0)
            for i in range(0, 1024):
                slave00_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 0, 0, 1020)
            m.put(slaves[0][0].qaddress, slave00_addr_state)

            self.assertEqual(slaves[0][1].index, 0)
            for i in range(0, 1024):
                slave01_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 0, 1, 1020)
            m.put(slaves[0][1].qaddress, slave01_addr_state)

            self.assertEqual(slaves[0][2].index, 5)
            for i in range(5, 1000):
                slave02_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 0, 2, 1018)
            m.put(slaves[0][2].qaddress, slave02_addr_state)

            walletd.get_slave(qaddress)
            slaves = walletd.get_slave_list(qaddress)
            self.assertEqual(len(slaves), 2)
            walletd._wallet.set_slave_ots_index(0, 0, 2, 1019)

            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[1][0].pk)), 0)
            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[1][1].pk)), 0)
            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[1][2].pk)), 0)
            slave10_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[1][0].qaddress))
            slave11_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[1][1].qaddress))
            slave12_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[1][2].qaddress))

            self.assertEqual(slaves[1][0].index, 0)
            for i in range(0, 1024):
                slave10_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 1, 0, 1020)
            m.put(slaves[1][0].qaddress, slave10_addr_state)

            self.assertEqual(slaves[1][1].index, 0)
            for i in range(0, 1024):
                slave11_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 1, 1, 1020)
            m.put(slaves[1][1].qaddress, slave11_addr_state)

            self.assertEqual(slaves[1][2].index, 5)
            for i in range(5, 1000):
                slave12_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 1, 2, 1018)
            m.put(slaves[1][2].qaddress, slave12_addr_state)

            walletd.get_slave(qaddress)
            slaves = walletd.get_slave_list(qaddress)
            self.assertEqual(len(slaves), 3)
            walletd._wallet.set_slave_ots_index(0, 1, 2, 1019)

            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[2][0].pk)), 0)
            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[2][1].pk)), 0)
            master_addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[2][2].pk)), 0)
            slave20_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[2][0].qaddress))
            slave21_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[2][1].qaddress))
            slave22_addr_state = AddressState.get_default(walletd.qaddress_to_address(slaves[2][2].qaddress))

            self.assertEqual(slaves[2][0].index, 0)
            for i in range(0, 1024):
                slave20_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 2, 0, 1020)
            m.put(slaves[2][0].qaddress, slave20_addr_state)

            self.assertEqual(slaves[2][1].index, 0)
            for i in range(0, 1024):
                slave21_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 2, 1, 1020)
            m.put(slaves[2][1].qaddress, slave21_addr_state)

            self.assertEqual(slaves[2][2].index, 5)
            for i in range(5, 1000):
                slave22_addr_state.set_ots_key(i)
            walletd._wallet.set_slave_ots_index(0, 2, 2, 1018)
            m.put(slaves[2][2].qaddress, slave22_addr_state)

            walletd.get_slave(qaddress)
            slaves = walletd.get_slave_list(qaddress)
            self.assertEqual(len(slaves), 4)
            walletd._wallet.set_slave_ots_index(0, 0, 2, 1019)

    def test_encrypt_last_item(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            walletd.authenticate()

            walletd.add_new_address(height=8)
            self.assertFalse(walletd.get_wallet_info()[2])
            walletd._passphrase = self.passphrase
            walletd._encrypt_last_item()
            self.assertTrue(walletd.get_wallet_info()[2])

    def test_get_wallet_index_xmss(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            index, xmss = walletd._get_wallet_index_xmss(qaddress, 0)
            self.assertEqual(index, 0)
            self.assertEqual(xmss.qaddress, qaddress)

    def test_add_new_address(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')
            self.assertEqual(len(walletd.list_address()), 1)

    def test_add_new_address2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')

            self.assertEqual(len(walletd.list_address()), 1)

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')

            self.assertEqual(len(walletd.list_address()), 2)

    def test_add_address_from_seed(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            qaddress1 = walletd.add_address_from_seed(seed=self.hex_seed)  # Using hexseed
            self.assertEqual(self.qaddress, qaddress1)

            self.assertEqual(len(walletd.list_address()), 1)

    def test_add_address_from_seed2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            qaddress1 = walletd.add_address_from_seed(seed=self.hex_seed)  # Using hexseed
            self.assertEqual(self.qaddress, qaddress1)

            self.assertEqual(len(walletd.list_address()), 1)

            walletd.remove_address(self.qaddress)
            self.assertEqual(len(walletd.list_address()), 0)

            qaddress2 = walletd.add_address_from_seed(seed=self.mnemonic)  # Using mnemonic
            self.assertEqual(self.qaddress, qaddress2)

            self.assertEqual(len(walletd.list_address()), 1)

    def test_list_address(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')

            self.assertEqual(len(walletd.list_address()), 1)
            list_address = walletd.list_address()
            self.assertEqual(list_address[0], qaddress)

    def test_remove_address(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')

            self.assertEqual(len(walletd.list_address()), 1)

            result = walletd.remove_address(qaddress)
            self.assertTrue(result)

            self.assertEqual(len(walletd.list_address()), 0)

    def test_remove_address2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')

            self.assertEqual(len(walletd.list_address()), 1)

            result = walletd.remove_address(qaddress)
            self.assertTrue(result)

            self.assertEqual(len(walletd.list_address()), 0)

            result = walletd.remove_address("Q123")
            self.assertFalse(result)

            self.assertEqual(len(walletd.list_address()), 0)

    def test_validate_address(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            qaddress = "Q010400ff39df1ba4d1d5b8753e6d04c51c34b95b01fc3650c10ca7b296a18bdc105412c59d0b3b"
            self.assertTrue(walletd.validate_address(qaddress))

            qaddress = "Q010400ff39df1ba4d1d5b8753e6d04c51c34b95b01fc3650c10ca7b296a18bdc105412c59d0b00"
            self.assertFalse(walletd.validate_address(qaddress))

    def test_get_recovery_seeds(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            self.assertEqual(qaddress[0], 'Q')

            seeds = walletd.get_recovery_seeds(qaddress)
            self.assertIsInstance(seeds, tuple)
            walletd.remove_address(qaddress)
            self.assertEqual(len(walletd.list_address()), 0)

            qaddress2 = walletd.add_address_from_seed(seeds[0])  # Using Hex Seed
            self.assertEqual(qaddress, qaddress2)
            walletd.remove_address(qaddress2)
            self.assertEqual(len(walletd.list_address()), 0)

            qaddress2 = walletd.add_address_from_seed(seeds[1])  # Using Mnemonic
            self.assertEqual(qaddress, qaddress2)
            walletd.remove_address(qaddress2)
            self.assertEqual(len(walletd.list_address()), 0)

    def test_get_wallet_info(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            version, len_address_items, encrypted = walletd.get_wallet_info()
            self.assertEqual(version, 1)
            self.assertEqual(len_address_items, 0)
            self.assertFalse(encrypted)

    def test_sign_and_push_transaction(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            alice_xmss = get_alice_xmss()
            bob_xmss = get_bob_xmss()
            tx = TransferTransaction.create(addrs_to=[bob_xmss.address],
                                            amounts=[1],
                                            message_data=None,
                                            fee=1,
                                            xmss_pk=alice_xmss.pk)

            walletd.sign_and_push_transaction(tx, alice_xmss, 0, enable_save=False)

            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.UNKNOWN))

            with self.assertRaises(Exception):
                walletd.sign_and_push_transaction(tx, alice_xmss, 0, enable_save=False)

    def test_relay_transfer_txn(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))
            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_transfer_txn(qaddresses_to=qaddresses_to,
                                            amounts=amounts,
                                            fee=100000000,
                                            master_qaddress=None,
                                            signer_address=qaddress,
                                            ots_index=0)
            self.assertIsNotNone(tx)

    def test_relay_transfer_txn2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))

            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_transfer_txn(qaddresses_to=qaddresses_to,
                                            amounts=amounts,
                                            fee=100000000,
                                            master_qaddress=None,
                                            signer_address=qaddress,
                                            ots_index=0)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_transfer_txn(qaddresses_to=qaddresses_to,
                                           amounts=amounts,
                                           fee=100000000,
                                           master_qaddress=None,
                                           signer_address=qaddress,
                                           ots_index=0)

    def test_relay_transfer_txn3(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            with self.assertRaises(Exception):
                walletd.relay_transfer_txn(qaddresses_to=qaddresses_to,
                                           amounts=amounts,
                                           fee=100000000,
                                           master_qaddress=None,
                                           signer_address=alice_xmss.qaddress,
                                           ots_index=0)

    def test_relay_transfer_txn_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_transfer_txn_by_slave(qaddresses_to=qaddresses_to,
                                                     amounts=amounts,
                                                     fee=100000000,
                                                     master_qaddress=qaddress)
            self.assertIsNotNone(tx)

    def test_relay_transfer_txn2_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_transfer_txn_by_slave(qaddresses_to=qaddresses_to,
                                                     amounts=amounts,
                                                     fee=100000000,
                                                     master_qaddress=qaddress)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_transfer_txn_by_slave(qaddresses_to=qaddresses_to,
                                                    amounts=amounts,
                                                    fee=100000000,
                                                    master_qaddress=qaddress)

    def test_relay_transfer_txn3_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))

            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            with self.assertRaises(Exception):
                walletd.relay_transfer_txn_by_slave(qaddresses_to=qaddresses_to,
                                                    amounts=amounts,
                                                    fee=100000000,
                                                    master_qaddress=alice_xmss.qaddress)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_transfer_txn_by_slave(qaddresses_to=qaddresses_to,
                                                    amounts=amounts,
                                                    fee=100000000,
                                                    master_qaddress=qaddress)

    def test_relay_message_txn(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))

            tx = walletd.relay_message_txn(message='Hello QRL!',
                                           fee=100000000,
                                           master_qaddress=None,
                                           signer_address=qaddress,
                                           ots_index=0)
            self.assertIsNotNone(tx)

    def test_relay_message_txn_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            tx = walletd.relay_message_txn_by_slave(message='Hello QRL!',
                                                    fee=100000000,
                                                    master_qaddress=qaddress)
            self.assertIsNotNone(tx)

    def test_relay_message_txn2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))
            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            tx = walletd.relay_message_txn(message='Hello QRL!',
                                           fee=100000000,
                                           master_qaddress=None,
                                           signer_address=qaddress,
                                           ots_index=0)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_message_txn(message='Hello QRL!',
                                          fee=100000000,
                                          master_qaddress=None,
                                          signer_address=qaddress,
                                          ots_index=0)

    def test_relay_message_txn2_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            tx = walletd.relay_message_txn_by_slave(message='Hello QRL!',
                                                    fee=100000000,
                                                    master_qaddress=qaddress)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_message_txn_by_slave(message='Hello QRL!',
                                                   fee=100000000,
                                                   master_qaddress=qaddress)

    def test_relay_token_txn(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))
            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_token_txn(symbol='QRL',
                                         name='Quantum Resistant Ledger',
                                         owner_qaddress=alice_xmss.qaddress,
                                         decimals=5,
                                         qaddresses=qaddresses,
                                         amounts=amounts,
                                         fee=100000000,
                                         master_qaddress=None,
                                         signer_address=qaddress,
                                         ots_index=0)
            self.assertIsNotNone(tx)

    def test_relay_token_txn_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_token_txn_by_slave(symbol='QRL',
                                                  name='Quantum Resistant Ledger',
                                                  owner_qaddress=alice_xmss.qaddress,
                                                  decimals=5,
                                                  qaddresses=qaddresses,
                                                  amounts=amounts,
                                                  fee=100000000,
                                                  master_qaddress=qaddress)
            self.assertIsNotNone(tx)

    def test_relay_token_txn2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))
            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_token_txn(symbol='QRL',
                                         name='Quantum Resistant Ledger',
                                         owner_qaddress=alice_xmss.qaddress,
                                         decimals=5,
                                         qaddresses=qaddresses,
                                         amounts=amounts,
                                         fee=100000000,
                                         master_qaddress=None,
                                         signer_address=qaddress,
                                         ots_index=0)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_token_txn(symbol='QRL',
                                        name='Quantum Resistant Ledger',
                                        owner_qaddress=alice_xmss.qaddress,
                                        decimals=5,
                                        qaddresses=qaddresses,
                                        amounts=amounts,
                                        fee=100000000,
                                        master_qaddress=None,
                                        signer_address=qaddress,
                                        ots_index=0)

    def test_relay_token_txn2_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]

            tx = walletd.relay_token_txn_by_slave(symbol='QRL',
                                                  name='Quantum Resistant Ledger',
                                                  owner_qaddress=alice_xmss.qaddress,
                                                  decimals=5,
                                                  qaddresses=qaddresses,
                                                  amounts=amounts,
                                                  fee=100000000,
                                                  master_qaddress=qaddress)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_token_txn_by_slave(symbol='QRL',
                                                 name='Quantum Resistant Ledger',
                                                 owner_qaddress=alice_xmss.qaddress,
                                                 decimals=5,
                                                 qaddresses=qaddresses,
                                                 amounts=amounts,
                                                 fee=100000000,
                                                 master_qaddress=qaddress)

    def test_relay_transfer_token_txn(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))

            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            tx = walletd.relay_transfer_token_txn(qaddresses_to=qaddresses_to,
                                                  amounts=amounts,
                                                  token_txhash='',
                                                  fee=100000000,
                                                  master_qaddress=None,
                                                  signer_address=qaddress,
                                                  ots_index=0)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_transfer_token_txn(qaddresses_to=qaddresses_to,
                                                 amounts=amounts,
                                                 token_txhash='',
                                                 fee=100000000,
                                                 master_qaddress=None,
                                                 signer_address=qaddress,
                                                 ots_index=0)

    def test_relay_transfer_token_txn2(self):
        """
        Relaying transfer token transaction from an address not listed in wallet daemon
        :return:
        """
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))

            walletd.add_new_address(height=8)
            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            with self.assertRaises(Exception):
                walletd.relay_transfer_token_txn(qaddresses_to=qaddresses_to,
                                                 amounts=amounts,
                                                 token_txhash='',
                                                 fee=100000000,
                                                 master_qaddress=None,
                                                 signer_address=alice_xmss.qaddress,
                                                 ots_index=0)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_transfer_token_txn(qaddresses_to=qaddresses_to,
                                                 amounts=amounts,
                                                 token_txhash='',
                                                 fee=100000000,
                                                 master_qaddress=None,
                                                 signer_address=qaddress,
                                                 ots_index=0)

    def test_relay_transfer_token_txn_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            qaddresses_to = [alice_xmss.qaddress, bob_xmss.qaddress]
            amounts = [1000000000, 1000000000]
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            tx = walletd.relay_transfer_token_txn_by_slave(qaddresses_to=qaddresses_to,
                                                           amounts=amounts,
                                                           token_txhash='',
                                                           fee=100000000,
                                                           master_qaddress=qaddress)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_transfer_token_txn_by_slave(qaddresses_to=qaddresses_to,
                                                          amounts=amounts,
                                                          token_txhash='',
                                                          fee=100000000,
                                                          master_qaddress=qaddress)

    def test_relay_slave_txn(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd._public_stub.IsSlave = Mock(
                return_value=qrl_pb2.IsSlaveResp(result=True))
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(next_unused_ots_index=0,
                                                unused_ots_index_found=True))

            qaddress = walletd.add_new_address(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            slave_pks = [alice_xmss.pk]
            access_types = [0]

            tx = walletd.relay_slave_txn(slave_pks=slave_pks,
                                         access_types=access_types,
                                         fee=100000000,
                                         master_qaddress=None,
                                         signer_address=qaddress,
                                         ots_index=0)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_slave_txn(slave_pks=slave_pks,
                                        access_types=access_types,
                                        fee=100000000,
                                        master_qaddress=None,
                                        signer_address=qaddress,
                                        ots_index=0)

    def test_relay_slave_txn_by_slave(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address_with_slaves(height=8)
            addr_state = AddressState.get_default(walletd.qaddress_to_address(qaddress))
            slaves = walletd.get_slave_list(qaddress)

            addr_state.add_slave_pks_access_type(bytes(hstr2bin(slaves[0][0].pk)), 0)
            walletd._public_stub.GetAddressState = Mock(
                return_value=qrl_pb2.GetAddressStateResp(state=addr_state.pbdata))

            walletd.encrypt_wallet(self.passphrase)
            walletd.unlock_wallet(self.passphrase)

            alice_xmss = get_alice_xmss(4)
            slave_pks = [alice_xmss.pk]
            access_types = [0]

            tx = walletd.relay_slave_txn_by_slave(slave_pks=slave_pks,
                                                  access_types=access_types,
                                                  fee=100000000,
                                                  master_qaddress=qaddress)
            self.assertIsNotNone(tx)

            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.relay_slave_txn_by_slave(slave_pks=slave_pks,
                                                 access_types=access_types,
                                                 fee=100000000,
                                                 master_qaddress=qaddress)

    def test_encrypt_wallet(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            with self.assertRaises(ValueError):
                walletd.encrypt_wallet(passphrase=self.passphrase)

            walletd.add_new_address()
            walletd.encrypt_wallet(passphrase=self.passphrase)

            with self.assertRaises(Exception):
                walletd.encrypt_wallet(passphrase=self.passphrase)

    def test_lock_wallet(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))
            walletd.add_new_address()
            walletd.encrypt_wallet(passphrase=self.passphrase)
            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.add_new_address()

    def test_unlock_wallet(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            walletd.add_new_address()
            walletd.encrypt_wallet(passphrase=self.passphrase)
            walletd.lock_wallet()
            with self.assertRaises(ValueError):
                walletd.add_new_address()
            with self.assertRaises(WalletDecryptionError):
                walletd.unlock_wallet(passphrase='pass123')
            walletd.unlock_wallet(passphrase=self.passphrase)
            walletd.add_new_address()
            self.assertEqual(len(walletd.list_address()), 2)

    def test_change_passphrase(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.PushTransaction = Mock(
                return_value=qrl_pb2.PushTransactionResp(error_code=qrl_pb2.PushTransactionResp.SUBMITTED))

            qaddress = walletd.add_new_address()
            walletd.encrypt_wallet(passphrase=self.passphrase)
            walletd.lock_wallet()

            passphrase2 = 'pass000'

            with self.assertRaises(ValueError):
                walletd.change_passphrase(old_passphrase='pass123', new_passphrase='pass234')
            walletd.change_passphrase(old_passphrase=self.passphrase, new_passphrase=passphrase2)

            with self.assertRaises(WalletDecryptionError):
                walletd.unlock_wallet(passphrase=self.passphrase)

            walletd.unlock_wallet(passphrase=passphrase2)
            qaddresses = walletd.list_address()
            self.assertEqual(len(qaddresses), 1)
            self.assertEqual(qaddresses[0], qaddress)

    def test_get_mini_transactions_by_address(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            walletd._public_stub.GetMiniTransactionsByAddress = Mock(
                return_value=qrl_pb2.GetMiniTransactionsByAddressResp(mini_transactions=[],
                                                                      balance=0))
            mini_transactions, balance = walletd.get_mini_transactions_by_address(
                qaddress=get_alice_xmss(4).qaddress,
                item_per_page=10,
                page_number=1
            )
            self.assertEqual(len(mini_transactions), 0)
            self.assertEqual(balance, 0)

    def test_get_transaction(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            tx = qrl_pb2.Transaction()
            tx.fee = 10
            tx.transaction_hash = b'1234'
            tx.message.message_hash = b'hello'
            pk = '01020016ecb9f39b9f4275d5a49e232346a15ae2fa8c50a2927daeac189b8c5f2d1' \
                 '8bc4e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e'
            tx.public_key = bytes(hstr2bin(pk))
            header_hash = 'ab'
            walletd._public_stub.GetTransaction = Mock(
                return_value=qrl_pb2.GetTransactionResp(tx=tx,
                                                        confirmations=10,
                                                        block_number=5,
                                                        block_header_hash=bytes(hstr2bin(header_hash))))
            tx, confirmations, block_number, block_header_hash = walletd.get_transaction(tx_hash='1234')
            self.assertIsNotNone(tx)
            self.assertEqual(tx.transaction_hash, bin2hstr(b'1234'))
            self.assertEqual(confirmations, "10")
            self.assertEqual(block_number, 5)
            self.assertEqual(block_header_hash, header_hash)

    def test_get_balance(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.GetBalance = Mock(
                return_value=qrl_pb2.GetBalanceResp(balance=1000))

            balance = walletd.get_balance(self.qaddress)
            self.assertEqual(balance, 1000)

    def test_get_total_balance(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            walletd._public_stub.GetTotalBalance = Mock(
                return_value=qrl_pb2.GetTotalBalanceResp(balance=6000))

            balance = walletd.get_total_balance()
            self.assertEqual(balance, 6000)

    def test_get_ots(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            ots_bitfield_by_page = qrl_pb2.OTSBitfieldByPage(ots_bitfield=[b'\x00'] * 10,
                                                             page_number=1)
            walletd._public_stub.GetOTS = Mock(
                return_value=qrl_pb2.GetOTSResp(ots_bitfield_by_page=[ots_bitfield_by_page],
                                                next_unused_ots_index=1,
                                                unused_ots_index_found=True))

            ots_bitfield_by_page, next_unused_ots_index, unused_ots_index_found = walletd.get_ots(self.qaddress)
            self.assertEqual(ots_bitfield_by_page, ots_bitfield_by_page)
            self.assertEqual(next_unused_ots_index, 1)
            self.assertEqual(unused_ots_index_found, True)

    def test_get_height(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            walletd._public_stub.GetHeight = Mock(
                return_value=qrl_pb2.GetHeightResp(height=1001))

            height = walletd.get_height()
            self.assertEqual(height, 1001)

    def test_get_block(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            block = qrl_pb2.Block()
            block.header.hash_header = b'001122'
            block.header.block_number = 1

            walletd._public_stub.GetBlock = Mock(
                return_value=qrl_pb2.GetBlockResp(block=block))

            b = walletd.get_block('001122')
            self.assertEqual(b.header.hash_header, bin2hstr(block.header.hash_header))
            self.assertEqual(b.header.block_number, block.header.block_number)

    def test_get_block_by_number(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()

            block = qrl_pb2.Block()
            block.header.hash_header = b'001122'
            block.header.block_number = 1

            walletd._public_stub.GetBlockByNumber = Mock(
                return_value=qrl_pb2.GetBlockResp(block=block))

            b = walletd.get_block_by_number(1)
            self.assertEqual(b.header.hash_header, bin2hstr(block.header.hash_header))
            self.assertEqual(b.header.block_number, block.header.block_number)

    def test_get_block_by_number2(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            alice = get_alice_xmss()
            message = b'\xaf\xaf\xa2\xe4\xfc\xabv\xdb\xe5\xbf\xe9(\x9a\xe5\xf5\xfb' \
                      b'\xe5\x9a\x13\xde+\xe5{D_\x05m\x06\x1c\x8f\nG?\xed\xd6qip3'

            tx = MessageTransaction.create(message_hash=message,
                                           addr_to=None,
                                           fee=1,
                                           xmss_pk=alice.pk)
            tx.sign(alice)

            block = qrl_pb2.Block()
            block.header.hash_header = b'001122'
            block.header.block_number = 1

            block.transactions.extend([tx.pbdata])

            walletd._public_stub.GetBlockByNumber = Mock(
                return_value=qrl_pb2.GetBlockResp(block=block))

            b = walletd.get_block_by_number(1)
            self.assertEqual(b.header.hash_header, bin2hstr(block.header.hash_header))
            self.assertEqual(b.header.block_number, block.header.block_number)

    def test_get_block_by_number3(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            alice = get_alice_xmss()

            message = b'\xaf\xaf\xa2B\x1f\xc7_\x1f\xfc;\xf5D^Hg\xb7R\x14\xa4Q\x82' \
                      b'\x1c \x9c\x861\x81\xa5\xdd\xe3\x81\x90\x89\xd6\xd4'

            tx = MessageTransaction.create(message_hash=message,
                                           addr_to=None,
                                           fee=1,
                                           xmss_pk=alice.pk)
            tx.sign(alice)

            block = qrl_pb2.Block()
            block.header.hash_header = b'001122'
            block.header.block_number = 1

            block.transactions.extend([tx.pbdata])

            walletd._public_stub.GetBlockByNumber = Mock(
                return_value=qrl_pb2.GetBlockResp(block=block))

            b = walletd.get_block_by_number(1)
            self.assertEqual(b.header.hash_header, bin2hstr(block.header.hash_header))
            self.assertEqual(b.header.block_number, block.header.block_number)

    def test_get_address_from_pk(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            pk = '01020016ecb9f39b9f4275d5a49e232346a15ae2fa8c50a2927daeac189b8c5f2d1' \
                 '8bc4e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e'

            address = walletd.get_address_from_pk(pk)
            self.assertEqual(address, 'Q010200670246b0026436b717f199e3ec5320ba6ab61d5eddff811ac199a9e9b871d3280178b343')

    def test_get_node_info(self):
        with set_qrl_dir("wallet_ver1"):
            walletd = WalletD()
            block_last_hash_str = 'c23f47a10a8c53cc5ded096369255a32c4a218682a961d0ee7db22c500000000'

            version = "1.0.0"
            num_connections = 10
            num_known_peers = 200
            uptime = 10000
            block_height = 102345
            block_last_hash = bytes(hstr2bin(block_last_hash_str))
            network_id = "network id"
            node_info = qrl_pb2.NodeInfo(version=version,
                                         num_connections=num_connections,
                                         num_known_peers=num_known_peers,
                                         uptime=uptime,
                                         block_height=block_height,
                                         block_last_hash=block_last_hash,
                                         network_id=network_id)
            walletd._public_stub.GetNodeState = Mock(
                return_value=qrl_pb2.GetNodeStateResp(info=node_info))

            b = walletd.get_node_info()
            self.assertEqual(b.info.version, version)
            self.assertEqual(b.info.num_connections, num_connections)
            self.assertEqual(b.info.num_known_peers, num_known_peers)
            self.assertEqual(b.info.uptime, uptime)
            self.assertEqual(b.info.block_height, block_height)
            self.assertEqual(b.info.block_last_hash, block_last_hash)
            self.assertEqual(b.info.network_id, network_id)
