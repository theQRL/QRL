# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from random import shuffle
from unittest import TestCase
from mock import Mock, PropertyMock, patch

from tests.misc.helper import get_alice_xmss, get_slave_xmss, get_random_xmss, set_qrl_dir
from qrl.core.misc import logger
from qrl.core import config
from qrl.core.State import State
from qrl.core.AddressState import AddressState
from qrl.core.OptimizedAddressState import OptimizedAddressState

logger.initialize_default()

alice = get_alice_xmss()
slave = get_slave_xmss()


class TestAddressState(TestCase):
    def setUp(self):
        self.addr_state = AddressState.get_default(alice.address)

    def test_create_and_properties(self):
        a = AddressState.create(address=alice.address, nonce=0, balance=10,
                                ots_bitfield=[b'\x00'] * config.dev.ots_bitfield_size,
                                tokens={b'010101': 100, b'020202': 200},
                                slave_pks_access_type={slave.pk: 1},
                                ots_counter=0
                                )
        self.assertEqual(a.pbdata.address, a.address)
        self.assertEqual(a.pbdata.balance, a.balance)
        a.balance = 3
        self.assertEqual(a.balance, 3)
        self.assertEqual(a.pbdata.nonce, a.nonce)
        self.assertEqual(a.pbdata.ots_bitfield, a.ots_bitfield)
        self.assertEqual(a.pbdata.ots_counter, a.ots_counter)
        self.assertEqual(a.pbdata.transaction_hashes, a.transaction_hashes)
        self.assertEqual(a.pbdata.latticePK_list, a.latticePK_list)
        self.assertEqual(a.pbdata.slave_pks_access_type, a.slave_pks_access_type)

    def test_token_balance_functionality(self):
        # If I update an AddressState's token balance, it should do what the function name says.
        self.addr_state.update_token_balance(b'010101', 10)
        self.assertEqual(self.addr_state.get_token_balance(b'010101'), 10)
        self.assertTrue(self.addr_state.is_token_exists(b'010101'))

        # I can call update_token_balance with a negative number to decrease the balance.
        self.addr_state.update_token_balance(b'010101', -2)
        self.assertEqual(self.addr_state.get_token_balance(b'010101'), 8)

        # If the token balance hits 0, the token_txhash should have been pruned from the AddressState.
        # And when I ask for its balance, it should return 0.
        self.addr_state.update_token_balance(b'010101', -8)
        self.assertFalse(self.addr_state.is_token_exists(b'010101'))
        self.assertEqual(self.addr_state.get_token_balance(b'010101'), 0)

    def test_nonce(self):
        self.addr_state.increase_nonce()
        self.assertEqual(self.addr_state.nonce, 1)

        self.addr_state.increase_nonce()
        self.addr_state.increase_nonce()
        self.assertEqual(self.addr_state.nonce, 3)

        self.addr_state.decrease_nonce()
        self.addr_state.decrease_nonce()
        self.assertEqual(self.addr_state.nonce, 1)

    def test_nonce_negative(self):
        with self.assertRaises(ValueError):
            self.addr_state.decrease_nonce()

    def test_slave_pks_access_type(self):
        # slave_pks_access_type could take 2 values: 0 (all permission granted to slaves), 1 (only mining)
        # There is no validation for the values of slave_pks_access_type.
        # For now only 0 is used.
        # By default all slave_pks get permission level 0
        self.addr_state.add_slave_pks_access_type(slave.pk, 1)
        self.assertEqual(self.addr_state.slave_pks_access_type[str(slave.pk)], 1)

    def test_get_slave_permission(self):
        # We haven't added slave.pk to the addr_state yet, so slave is not yet a slave of this AddressState.
        self.assertEqual(self.addr_state.get_slave_permission(slave.pk), -1)

        # Add slave permissions for slave.pk
        self.addr_state.add_slave_pks_access_type(slave.pk, 1)
        self.assertEqual(self.addr_state.get_slave_permission(slave.pk), 1)

        # Remove slave permissions for slave.pk
        self.addr_state.remove_slave_pks_access_type(slave.pk)
        self.assertEqual(self.addr_state.get_slave_permission(slave.pk), -1)

    def test_get_default_coinbase(self):
        # Make sure that Coinbase AddressState gets all the coins supply by default
        coinbase_addr_state = AddressState.get_default(config.dev.coinbase_address)
        self.assertEqual(coinbase_addr_state.balance, int(config.dev.max_coin_supply * config.dev.shor_per_quanta))

    def test_set_ots_key(self):
        # If it's below config.dev.max_ots_tracking_index, use the bitfield.
        self.assertEqual(b'\x00', self.addr_state.ots_bitfield[0])
        self.addr_state.set_ots_key(0)
        self.assertEqual(b'\x01', self.addr_state.ots_bitfield[0])
        self.assertEqual(self.addr_state.ots_counter, 0)

        self.assertEqual(b'\x00', self.addr_state.ots_bitfield[-1])
        self.addr_state.set_ots_key(config.dev.max_ots_tracking_index - 1)
        self.assertEqual(b'\x80', self.addr_state.ots_bitfield[-1])

        # Start using the counter from config.dev.max_ots_tracking_index and above.
        self.addr_state.set_ots_key(config.dev.max_ots_tracking_index)
        self.assertEqual(self.addr_state.ots_counter, config.dev.max_ots_tracking_index)
        self.addr_state.set_ots_key(config.dev.max_ots_tracking_index + 1)
        self.assertEqual(self.addr_state.ots_counter, config.dev.max_ots_tracking_index + 1)

    def test_unset_ots_key(self):
        m_state = Mock(name='mock State')
        # Set the OTS bitfield, and then try to unset it.
        self.addr_state.set_ots_key(0)
        self.addr_state.unset_ots_key(0, m_state)
        self.assertEqual(self.addr_state.ots_bitfield[0], b'\x00')

    @patch('qrl.core.AddressState.AddressState.transaction_hashes', new_callable=PropertyMock)
    def test_unset_ots_key_counter(self, m_transaction_hashes):
        # unset_ots_key() walks backwards through transaction_hashes and finds the last txhash that used OTS counter
        # index.
        # This assumes that transaction_hashes is sorted in time-ascending order, and that the offending tx
        # has already been removed from transaction_hashes.
        m_transaction_hashes.return_value = ["1st hash", "2nd hash", "3rd hash", "4th hash"]
        m_state = Mock(name='mock State')

        # The user has used some OTS bitfield indexes in a random fashion, and has two OTS counter transactions.
        m_state.get_tx_metadata.side_effect = [
            (Mock(name="4th hash", ots_key=357), "unused"),
            (Mock(name="3rd hash", ots_key=config.dev.max_ots_tracking_index + 3), "unused"),
            (Mock(name="2nd hash", ots_key=952), "unused"),
            (Mock(name="1st hash", ots_key=config.dev.max_ots_tracking_index + 2), "unused")
        ]
        self.addr_state.set_ots_key(config.dev.max_ots_tracking_index + 4)  # 8196

        # You must remove the txhash that uses index 8196 from transaction_hashes BEFORE calling this function, as it
        # will walk backwards through the transaction_hashes
        self.addr_state.unset_ots_key(config.dev.max_ots_tracking_index + 4, m_state)

        self.assertEqual(self.addr_state.ots_counter, config.dev.max_ots_tracking_index + 3)

    @patch('qrl.core.AddressState.AddressState.transaction_hashes', new_callable=PropertyMock)
    def test_unset_ots_key_counter_unsorted_transaction_hashes(self, m_transaction_hashes):
        # unset_ots_key() ends up with the wrong OTS counter index if transaction_hashes is not properly sorted.
        m_transaction_hashes.return_value = ["1st hash", "2nd hash", "3rd hash", "4th hash"]
        m_state = Mock(name='mock State')

        # The user has used some OTS bitfield indexes in a random fashion, and has two OTS counter transactions.
        m_state.get_tx_metadata.side_effect = [
            (Mock(name="4th hash", ots_key=357), "unused"),
            (Mock(name="3rd hash", ots_key=config.dev.max_ots_tracking_index + 2), "unused"),
            (Mock(name="2nd hash", ots_key=952), "unused"),
            (Mock(name="1st hash", ots_key=config.dev.max_ots_tracking_index + 3), "unused")
        ][-1::-1]  # reversing the order, as it will be called in reverse order by unset_ots_key
        self.addr_state.set_ots_key(config.dev.max_ots_tracking_index + 4)  # 8196

        self.addr_state.unset_ots_key(config.dev.max_ots_tracking_index + 4, m_state)

        # In a perfect world, unset_ots_key should have found "1st hash" and used its ots_key
        # But it found "3rd hash" and used its ots key, thus FAIL.
        self.assertEqual(self.addr_state.ots_counter, config.dev.max_ots_tracking_index + 3)

    def test_ots_key_validation(self):
        random_xmss = get_random_xmss(xmss_height=4)
        addr = AddressState.get_default(random_xmss.address)
        ots_indexes = list(range(0, 2 ** random_xmss.height))
        shuffle(ots_indexes)

        for i in ots_indexes:
            if i < config.dev.max_ots_tracking_index:
                self.assertFalse(addr.ots_key_reuse(i))
            else:
                result = addr.ots_key_reuse(i)
                if i > addr.ots_counter:
                    self.assertFalse(result)
                else:
                    self.assertTrue(result)

            addr.set_ots_key(i)

            self.assertTrue(addr.ots_key_reuse(i))

    def test_ots_key_reuse_counter(self):
        # If the ots counter is 8193, that automatically means index 8192 is used.
        self.addr_state.set_ots_key(config.dev.max_ots_tracking_index + 1)
        self.assertTrue(self.addr_state.ots_key_reuse(config.dev.max_ots_tracking_index))
        # If the ots counter is 8193, that means 8194 and above are not used.
        self.assertFalse(self.addr_state.ots_key_reuse(config.dev.max_ots_tracking_index + 2))

    def test_serialize(self):
        # Simply test that serialize() works and you can deserialize from it.
        output = self.addr_state.serialize()
        another_addr_state = AddressState(protobuf_block=output)
        self.assertIsInstance(another_addr_state, AddressState)

    def test_address_is_valid(self):
        self.assertTrue(AddressState.address_is_valid(alice.address))
        self.assertFalse(AddressState.address_is_valid(b'fake address'))

    def test_height(self):
        self.assertEqual(self.addr_state.height, alice.address[1] << 1)

    def test_get_unused_ots_index(self):
        random_xmss = get_random_xmss(xmss_height=4)
        addr_state = AddressState.get_default(random_xmss.address)
        self.assertEqual(addr_state.get_unused_ots_index(), 0)
        addr_state.set_ots_key(0)
        self.assertEqual(addr_state.get_unused_ots_index(), 1)
        addr_state.set_ots_key(2)
        self.assertEqual(addr_state.get_unused_ots_index(), 1)
        addr_state.set_ots_key(1)
        self.assertEqual(addr_state.get_unused_ots_index(), 3)
        for i in range(3, min(2 ** addr_state.height, config.dev.max_ots_tracking_index)):
            addr_state.set_ots_key(i)
        self.assertIsNone(addr_state.get_unused_ots_index())

    def test_get_unused_ots_index2(self):
        old_value = config.dev.max_ots_tracking_index
        config.dev.max_ots_tracking_index = 128

        try:
            random_xmss = get_random_xmss(xmss_height=8)
            addr_state = AddressState.get_default(random_xmss.address)
            self.assertEqual(addr_state.get_unused_ots_index(), 0)
            addr_state.set_ots_key(0)
            self.assertEqual(addr_state.get_unused_ots_index(), 1)
            addr_state.set_ots_key(2)
            self.assertEqual(addr_state.get_unused_ots_index(), 1)
            addr_state.set_ots_key(1)
            self.assertEqual(addr_state.get_unused_ots_index(), 3)

            for i in range(3, min(2 ** addr_state.height, config.dev.max_ots_tracking_index)):
                addr_state.set_ots_key(i)
                self.assertEqual(addr_state.get_unused_ots_index(), i + 1)

            self.assertEqual(addr_state.get_unused_ots_index(), config.dev.max_ots_tracking_index)

            for i in range(config.dev.max_ots_tracking_index, 2 ** addr_state.height):
                addr_state.set_ots_key(i)

            self.assertIsNone(addr_state.get_unused_ots_index())
        finally:
            config.dev.max_ots_tracking_index = old_value

    def test_return_all_addresses(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(AddressState.return_all_addresses(state), [])

    def test_put_addresses_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                alice_state = OptimizedAddressState.get_default(alice_xmss.address)
                addresses_state = {
                    alice_state.address: alice_state,
                    b'test1': OptimizedAddressState.get_default(b'test1')
                }
                AddressState.put_addresses_state(state, addresses_state, None)
                alice_state2 = OptimizedAddressState.get_optimized_address_state(state, alice_xmss.address)
                self.assertEqual(alice_state.serialize(), alice_state2.serialize())
                test_state = OptimizedAddressState.get_optimized_address_state(state, b'test1')
                self.assertEqual(test_state.serialize(), OptimizedAddressState.get_default(b'test1').serialize())
