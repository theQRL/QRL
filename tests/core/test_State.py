# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.Transaction import TransferTokenTransaction
from tests.misc.helper import set_data_dir, get_alice_xmss, get_bob_xmss, get_token_transaction

logger.initialize_default()


class TestState(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestState, self).__init__(*args, **kwargs)

    def test_create_state(self):
        with set_data_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

    def test_release_state(self):
        with set_data_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

    def test_set_block_pos(self):
        with set_data_dir('no_data'):
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

                alice_address = alice_xmss.get_address()
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

                alice_address = bytearray(alice_xmss.get_address())
                with self.assertRaises(TypeError):
                    address_state = state.get_address(alice_address)

                alice_address = alice_xmss.get_address()
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))
                state._save_address_state(address_state)

                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_get_address2(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                alice_address = alice_xmss.get_address()
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))
                state._save_address_state(address_state)
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_create_token_metadata(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                token_transaction = get_token_transaction(alice_xmss, bob_xmss)
                state.create_token_metadata(token_transaction)

                token_metadata = state.get_token_metadata(token_transaction.txhash)
                self.assertEqual(token_metadata.token_txhash, token_transaction.txhash)
                self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)

    def test_update_token_metadata(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                token_transaction = get_token_transaction(alice_xmss, bob_xmss)
                state.create_token_metadata(token_transaction)

                transfer_token_transaction = TransferTokenTransaction.create(addr_from=bob_xmss.get_address(),
                                                                             token_txhash=token_transaction.txhash,
                                                                             addr_to=alice_xmss.get_address(),
                                                                             amount=100000000,
                                                                             fee=1,
                                                                             xmss_pk=bob_xmss.pk(),
                                                                             xmss_ots_index=bob_xmss.get_index())

                state.update_token_metadata(transfer_token_transaction)

                token_metadata = state.get_token_metadata(token_transaction.txhash)
                self.assertEqual(len(token_metadata.transfer_token_tx_hashes), 2)
                self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)
                self.assertEqual(token_metadata.transfer_token_tx_hashes[1], transfer_token_transaction.txhash)
