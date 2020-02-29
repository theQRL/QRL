# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from mock import PropertyMock, patch
import random
from math import ceil

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedBitfield import PaginatedBitfield
from tests.misc.helper import get_alice_xmss, get_slave_xmss, set_qrl_dir

logger.initialize_default()

alice = get_alice_xmss()
slave = get_slave_xmss()


class TestPaginatedBitfield(TestCase):
    def setUp(self):
        pass

    def test_generate_bitfield_key(self):
        with set_qrl_dir('no_data'):
            state = State()
            paginated_bitfield = PaginatedBitfield(True, state._db)
            address = b'addr1'
            page = 1
            expected_key = b'bitfield_' + address + b'_' + page.to_bytes(8, byteorder='big', signed=False)
            found_key = paginated_bitfield.generate_bitfield_key(address, page)
            self.assertEqual(expected_key, found_key)

    def test_load_bitfield_and_ots_key_reuse(self):
        with set_qrl_dir('no_data'):
            state = State()
            alice_xmss = get_alice_xmss(4)
            paginated_bitfield = PaginatedBitfield(True, state._db)
            self.assertFalse(paginated_bitfield.load_bitfield_and_ots_key_reuse(alice_xmss.address,
                                                                                0))
            addresses_state = {
                alice_xmss.address: OptimizedAddressState.get_default(alice_xmss.address)
            }
            paginated_bitfield.set_ots_key(addresses_state, alice_xmss.address, 0)
            self.assertTrue(paginated_bitfield.load_bitfield_and_ots_key_reuse(alice_xmss.address,
                                                                               0))

    @patch('qrl.core.config.DevConfig.ots_tracking_per_page', new_callable=PropertyMock, return_value=1024)
    @patch('qrl.core.config.DevConfig.ots_bitfield_size', new_callable=PropertyMock)
    def test_ots_key_reuse(self, mock_ots_bitfield_size, mock_ots_tracking_per_page):
        """
        Randomly using OTS key
        :return:
        """
        with set_qrl_dir('no_data'):
            state = State()

            mock_ots_bitfield_size.return_value = ceil(config.dev.ots_tracking_per_page / 8)
            paginated_bitfield = PaginatedBitfield(True, state._db)

            alice_xmss = get_alice_xmss(12)
            address = alice_xmss.address
            address_state = OptimizedAddressState.get_default(address)
            addresses_state = {address: address_state}
            bitfield_data = paginated_bitfield.get_paginated_data(address, 1)
            self.assertFalse(paginated_bitfield.ots_key_reuse(bitfield_data, 0))

            paginated_bitfield.set_ots_key(addresses_state, address, 0)
            bitfield_data = paginated_bitfield.get_paginated_data(address, 1)
            # False, as bitfield has been set but has not been written to state.
            self.assertFalse(paginated_bitfield.ots_key_reuse(bitfield_data, 0))

            # Writing bitfield to the state.
            paginated_bitfield.put_addresses_bitfield(None)
            bitfield_data = paginated_bitfield.get_paginated_data(address, 1)
            self.assertTrue(paginated_bitfield.ots_key_reuse(bitfield_data, 0))

    @patch('qrl.core.config.DevConfig.ots_tracking_per_page', new_callable=PropertyMock, return_value=1024)
    @patch('qrl.core.config.DevConfig.ots_bitfield_size', new_callable=PropertyMock)
    def test_set_ots_key(self, mock_ots_bitfield_size, mock_ots_tracking_per_page):
        """
        Randomly using OTS key
        :return:
        """
        with set_qrl_dir('no_data'):
            state = State()
            mock_ots_bitfield_size.return_value = ceil(config.dev.ots_tracking_per_page / 8)

            alice_xmss = get_alice_xmss(12)
            address = alice_xmss.address
            address_state = OptimizedAddressState.get_default(address)
            addresses_state = {address: address_state}
            paginated_bitfield = PaginatedBitfield(True, state._db)
            paginated_bitfield.update_used_page_in_address_state(address, addresses_state, 1)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(3072, 2 ** alice_xmss.height))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(2048, 3072))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(1024, 2048))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(0, 1024))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                if i == ots_indexes[-1]:
                    self.assertEqual(address_state.ots_bitfield_used_page, 4)

            self.assertEqual(address_state.ots_bitfield_used_page, 4)

    @patch('qrl.core.config.DevConfig.ots_tracking_per_page', new_callable=PropertyMock, return_value=1024)
    @patch('qrl.core.config.DevConfig.ots_bitfield_size', new_callable=PropertyMock)
    def test_set_ots_key2(self, mock_ots_bitfield_size, mock_ots_tracking_per_page):
        """
        Randomly using OTS key
        :return:
        """
        with set_qrl_dir('no_data'):
            state = State()
            mock_ots_bitfield_size.return_value = ceil(config.dev.ots_tracking_per_page / 8)

            alice_xmss = get_alice_xmss(12)
            address = alice_xmss.address
            address_state = OptimizedAddressState.get_default(address)
            addresses_state = {address: address_state}
            paginated_bitfield = PaginatedBitfield(True, state._db)
            paginated_bitfield.update_used_page_in_address_state(address, addresses_state, 1)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(0, 2**alice_xmss.height))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                if i == ots_indexes[-1]:
                    self.assertEqual(address_state.ots_bitfield_used_page, 4)

            self.assertEqual(address_state.ots_bitfield_used_page, 4)

    @patch('qrl.core.config.DevConfig.ots_tracking_per_page', new_callable=PropertyMock, return_value=1024)
    @patch('qrl.core.config.DevConfig.ots_bitfield_size', new_callable=PropertyMock)
    def test_unset_ots_key(self, mock_ots_bitfield_size, mock_ots_tracking_per_page):
        """
        Randomly using OTS key
        :return:
        """
        with set_qrl_dir('no_data'):
            state = State()
            mock_ots_bitfield_size.return_value = ceil(config.dev.ots_tracking_per_page / 8)

            alice_xmss = get_alice_xmss(12)
            address = alice_xmss.address
            address_state = OptimizedAddressState.get_default(address)
            addresses_state = {address: address_state}
            paginated_bitfield = PaginatedBitfield(True, state._db)
            paginated_bitfield.update_used_page_in_address_state(address, addresses_state, 1)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(3072, 2 ** alice_xmss.height))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(2048, 3072))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(1024, 2048))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(0, 1024))
            random.shuffle(ots_indexes)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                if i == ots_indexes[-1]:
                    self.assertEqual(address_state.ots_bitfield_used_page, 4)
                else:
                    self.assertEqual(address_state.ots_bitfield_used_page, 0)

            self.assertEqual(address_state.ots_bitfield_used_page, 4)

            paginated_bitfield.unset_ots_key(addresses_state, address, 2049)
            self.assertEqual(address_state.ots_bitfield_used_page, 2)

            paginated_bitfield.unset_ots_key(addresses_state, address, 1023)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            paginated_bitfield.set_ots_key(addresses_state, address, 1023)
            self.assertEqual(address_state.ots_bitfield_used_page, 2)

    @patch('qrl.core.config.DevConfig.ots_tracking_per_page', new_callable=PropertyMock, return_value=1024)
    @patch('qrl.core.config.DevConfig.ots_bitfield_size', new_callable=PropertyMock)
    def test_unset_ots_key2(self, mock_ots_bitfield_size, mock_ots_tracking_per_page):
        """
        Randomly using OTS key
        :return:
        """
        with set_qrl_dir('no_data'):
            state = State()
            mock_ots_bitfield_size.return_value = ceil(config.dev.ots_tracking_per_page / 8)

            alice_xmss = get_alice_xmss(12)
            address = alice_xmss.address
            address_state = OptimizedAddressState.get_default(address)
            addresses_state = {address: address_state}
            paginated_bitfield = PaginatedBitfield(True, state._db)
            paginated_bitfield.update_used_page_in_address_state(address, addresses_state, 1)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            ots_indexes = list(range(1, 2**alice_xmss.height))
            random.shuffle(ots_indexes)
            ots_indexes.append(0)
            for i in ots_indexes:
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                if i == ots_indexes[-1]:
                    self.assertEqual(address_state.ots_bitfield_used_page, 4)
                else:
                    self.assertEqual(address_state.ots_bitfield_used_page, 0)

            self.assertEqual(address_state.ots_bitfield_used_page, 4)

            paginated_bitfield.unset_ots_key(addresses_state, address, 4095)
            self.assertEqual(address_state.ots_bitfield_used_page, 3)

            paginated_bitfield.unset_ots_key(addresses_state, address, 3000)
            self.assertEqual(address_state.ots_bitfield_used_page, 2)

            paginated_bitfield.unset_ots_key(addresses_state, address, 2000)
            self.assertEqual(address_state.ots_bitfield_used_page, 1)

            paginated_bitfield.unset_ots_key(addresses_state, address, 1000)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            paginated_bitfield.set_ots_key(addresses_state, address, 1000)
            self.assertEqual(address_state.ots_bitfield_used_page, 1)

            paginated_bitfield.set_ots_key(addresses_state, address, 2000)
            self.assertEqual(address_state.ots_bitfield_used_page, 2)

            paginated_bitfield.set_ots_key(addresses_state, address, 3000)
            self.assertEqual(address_state.ots_bitfield_used_page, 3)

            paginated_bitfield.set_ots_key(addresses_state, address, 4095)
            self.assertEqual(address_state.ots_bitfield_used_page, 4)

    @patch('qrl.core.config.DevConfig.ots_tracking_per_page', new_callable=PropertyMock, return_value=1024)
    @patch('qrl.core.config.DevConfig.ots_bitfield_size', new_callable=PropertyMock)
    def test_unset_ots_key3(self, mock_ots_bitfield_size, mock_ots_tracking_per_page):
        """
        Features Tested
        - Sequentially marking OTS indexes as used
        - Sequentially marking OTS indexes as unused
        - ots_bitfield_used_page value with each OTS index being used

        Expectation
        - The ots_bitfield_used_page must increase by 1 for every sequential 1024 (ots_tracking_per_page) ots indexes
          marked as used

        :param mock_ots_bitfield_size:
        :param mock_ots_tracking_per_page:
        :return:
        """
        with set_qrl_dir('no_data'):
            state = State()
            mock_ots_bitfield_size.return_value = ceil(config.dev.ots_tracking_per_page / 8)

            alice_xmss = get_alice_xmss(12)
            address = alice_xmss.address
            address_state = OptimizedAddressState.get_default(address)
            addresses_state = {address: address_state}
            paginated_bitfield = PaginatedBitfield(True, state._db)
            paginated_bitfield.update_used_page_in_address_state(address, addresses_state, 1)
            self.assertEqual(address_state.ots_bitfield_used_page, 0)

            total_ots = 2 ** alice_xmss.height
            for i in range(0, total_ots + 1):
                paginated_bitfield.set_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, (i + 1) // config.dev.ots_tracking_per_page)

            self.assertEqual(address_state.ots_bitfield_used_page,
                             total_ots // config.dev.ots_tracking_per_page)
            self.assertEqual(total_ots // config.dev.ots_tracking_per_page, 4)

            paginated_bitfield.unset_ots_key(addresses_state, address, total_ots - 1)
            self.assertEqual(address_state.ots_bitfield_used_page, 3)

            for i in range(total_ots - 2, -1, -1):
                paginated_bitfield.unset_ots_key(addresses_state, address, i)
                self.assertEqual(address_state.ots_bitfield_used_page, i // config.dev.ots_tracking_per_page)
