# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from mock import patch, PropertyMock
from unittest import TestCase

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.PaginatedData import PaginatedData
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.State import State

from tests.misc.helper import set_qrl_dir, get_alice_xmss

logger.initialize_default()


class TestPaginatedData(TestCase):
    def setUp(self):
        self.alice = get_alice_xmss()

    def test_reset_key_value(self):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)

            self.assertEqual(len(p.key_value), 0)

            p.key_value[b'a'] = [10]
            self.assertEqual(len(p.key_value), 1)

            p.reset_key_value()
            self.assertEqual(len(p.key_value), 0)

    def test_get_value(self):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            storage_key = p.generate_key(b'a', 0)
            p.key_value[storage_key] = [10]
            self.assertEqual(p.get_value(b'a', 0), [10])

    def test_insert(self):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)

            p.insert(OptimizedAddressState.get_default(b'a'), b'10')
            self.assertEqual(p.get_value(b'a', 0), [b'10'])

    @patch('qrl.core.config.DevConfig.data_per_page', new_callable=PropertyMock, return_value=10)
    def test_put_paginated_data(self, mock_dev_config):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)

            for i in range(0, 10):
                p.insert(alice_address_state, b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))
                self.assertEqual(alice_address_state.get_counter_by_name(p.name), i + 1)

            p.put_paginated_data(None)
            self.assertEqual(alice_address_state.get_counter_by_name(p.name), 10)

            for i in range(10, 25):
                p.insert(alice_address_state, b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))
                self.assertEqual(alice_address_state.get_counter_by_name(p.name), i + 1)

            p.put_paginated_data(None)
            self.assertEqual(alice_address_state.get_counter_by_name(p.name), 25)
            self.assertEqual(len(p.key_value), 0)

            pages_data = []
            for i in range(0, (25 // config.dev.data_per_page) + 1):
                data = p.get_paginated_data(self.alice.address,
                                            (i + 1) * config.dev.data_per_page - 1)
                pages_data.append(data)

            self.assertEqual(len(pages_data), 3)

            self.assertEqual(len(pages_data[0]), 10)
            for i in range(0, 10):
                self.assertEqual(pages_data[0][i], b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))

            self.assertEqual(len(pages_data[1]), 10)
            for i in range(10, 20):
                self.assertEqual(pages_data[1][i - 10], b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))

            self.assertEqual(len(pages_data[2]), 5)
            for i in range(20, 25):
                self.assertEqual(pages_data[2][i - 20], b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))

    @patch('qrl.core.config.DevConfig.data_per_page', new_callable=PropertyMock, return_value=10)
    def test_revert_paginated_data(self, mock_dev_config):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)

            for i in range(0, 25):
                p.insert(alice_address_state, b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))
            p.put_paginated_data(None)

            full_hash = []
            for i in range(0, (25 // config.dev.data_per_page) + 1):
                data = p.get_paginated_data(self.alice.address,
                                            (i + 1) * config.dev.data_per_page - 1)
                full_hash.extend(data)

            for tx_hash in full_hash[24:18:-1]:
                p.remove(alice_address_state, tx_hash)
            p.put_paginated_data(None)

            self.assertEqual(alice_address_state.get_counter_by_name(b'p_tx_hash'),
                             19)

            # page 2 data count must be 0
            self.assertEqual(len(p.get_paginated_data(alice_address_state.address, 2 * config.dev.data_per_page)),
                             0)

            # page 1 data count must be 9
            self.assertEqual(len(p.get_paginated_data(alice_address_state.address, config.dev.data_per_page)),
                             9)

            # page 0 data count must be 10
            self.assertEqual(len(p.get_paginated_data(alice_address_state.address, 0)),
                             10)

    @patch('qrl.core.config.DevConfig.data_per_page', new_callable=PropertyMock, return_value=10)
    def test_revert_paginated_data2(self, mock_dev_config):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)

            for i in range(0, 25):
                p.insert(alice_address_state, b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False))

            p.put_paginated_data(None)

            full_hash = []
            for i in range(0, (25 // config.dev.data_per_page) + 1):
                data = p.get_paginated_data(self.alice.address,
                                            (i + 1) * config.dev.data_per_page - 1)
                full_hash.extend(data)

            for tx_hash in full_hash[-1::-1]:
                p.remove(alice_address_state, tx_hash)
            p.put_paginated_data(None)

            self.assertEqual(alice_address_state.get_counter_by_name(b'p_tx_hash'),
                             0)

            self.assertEqual(len(p.get_paginated_data(alice_address_state.address, 22)),
                             0)

            self.assertEqual(len(p.get_paginated_data(alice_address_state.address, 12)),
                             0)

            self.assertEqual(len(p.get_paginated_data(alice_address_state.address, 2)),
                             0)

    @patch('qrl.core.config.DevConfig.data_per_page', new_callable=PropertyMock, return_value=10)
    def test_get_paginated_data(self, mock_dev_config):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)

            total_hashes = 25
            expected_full_hash = []
            for i in range(0, total_hashes):
                tx_hash = b'p_tx_hash_' + i.to_bytes(8, byteorder='big', signed=False)
                p.insert(alice_address_state, tx_hash)
                expected_full_hash.append(tx_hash)

            p.put_paginated_data(None)

            found_full_hash = []
            expected_data_count = [10, 10, 5]
            for i in range(0, (total_hashes // config.dev.data_per_page) + 1):
                data = p.get_paginated_data(self.alice.address,
                                            (i + 1) * config.dev.data_per_page - 1)
                self.assertEqual(len(data), expected_data_count[i])
                found_full_hash.extend(data)

            self.assertEqual(expected_full_hash, found_full_hash)

    @patch('qrl.core.config.DevConfig.data_per_page', new_callable=PropertyMock, return_value=10)
    def test_put(self, mock_dev_config):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            key = b'test_key'
            value = [b'hello world']
            storage_key = p.generate_key(key, 11)
            p.put(storage_key, value, None)
            found_value = p.get_paginated_data(key, 11)
            self.assertEqual(value, found_value)

    @patch('qrl.core.config.DevConfig.data_per_page', new_callable=PropertyMock, return_value=10)
    def test_remove(self, mock_dev_config):
        with set_qrl_dir('no_data'):
            state = State()
            p = PaginatedData(b'p_tx_hash', True, state._db)
            key = b'test_key'
            value = [b'hello world']
            storage_key = p.generate_key(key, 11)
            p.put(storage_key, value, None)
            found_value = p.get_paginated_data(key, 11)
            self.assertEqual(value, found_value)

            p.delete(storage_key, None)
            found_value = p.get_paginated_data(key, 11)
            self.assertEqual([], found_value)
