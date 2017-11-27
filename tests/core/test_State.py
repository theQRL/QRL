# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.State import State
from qrl.crypto.misc import sha256
from tests.misc.helper import set_data_dir, get_alice_xmss

logger.initialize_default(force_console_output=True)


class TestState(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestState, self).__init__(*args, **kwargs)

    def test_create_state(self):
        with State() as state:
            self.assertIsNotNone(state)  # to avoid warning (unused variable)

    def test_set_block_pos(self):
        with State() as state:
            block_number = 123

            block_position = 234
            block_size = 345

            state._db.put('block_{}'.format(block_number), [block_position, block_size])

            pos_size = state._db.get('block_{}'.format(block_number))
            read_position, read_size = pos_size

            self.assertEqual(block_position, read_position)
            self.assertEqual(block_size, read_size)

    def test_get_address(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                alice_address = bytes(alice_xmss.get_address().encode())  # FIXME: This needs to be refactored
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

                alice_address = bytearray(alice_xmss.get_address().encode())  # FIXME: This needs to be refactored
                with self.assertRaises(TypeError):
                    address_state = state.get_address(alice_address)

                alice_address = bytes(alice_xmss.get_address().encode())  # FIXME: This needs to be refactored
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))
                state._save_address_state(address_state)

                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_get_address2(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                alice_address = bytes(alice_xmss.get_address().encode())
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))
                state._save_address_state(address_state)
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_addr_tx_hashes(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                alice_address = bytes(alice_xmss.get_address().encode())  # FIXME: This needs to be refactored
                some_hash1 = sha256(b'some_hash1')
                some_hash2 = sha256(b'some_hash2')

                state.update_address_tx_hashes(alice_address, some_hash1)
                state.update_address_tx_hashes(alice_address, some_hash2)
                result = state.get_address_tx_hashes(alice_address)

                self.assertEqual(some_hash1, result[0])
                self.assertEqual(some_hash2, result[1])
