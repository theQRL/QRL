# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
import mock

from pyqrllib.pyqrllib import sha2_256, bin2hstr

from qrl.core import config
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.misc import logger, db
from qrl.core.AddressState import AddressState
from qrl.core.State import State, StateLoader
from qrl.core.Transaction import TransferTokenTransaction
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.generated import qrl_pb2
from tests.misc.helper import set_data_dir, get_alice_xmss, get_bob_xmss, get_token_transaction, \
    set_default_balance_size

logger.initialize_default()


def gen_blocks(block_count, state, miner_address):
        blocks = []
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948
            prev_hash = bytes(sha2_256(b'test'))
            for i in range(0, block_count):
                block = Block.create(block_number=i,
                                     prevblock_headerhash=prev_hash,
                                     transactions=[],
                                     miner_address=miner_address)
                block.set_mining_nonce(10)
                blocks.append(block)

                metadata = BlockMetadata()
                metadata.set_block_difficulty(256)
                state.put_block_metadata(block.headerhash, metadata, None)

                state.put_block(block, None)
                prev_hash = bytes(block.headerhash)

        return blocks


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

                alice_address = alice_xmss.address
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

                alice_address = bytearray(alice_xmss.address)
                with self.assertRaises(TypeError):
                    address_state = state.get_address(alice_address)

                alice_address = alice_xmss.address
                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))
                state._save_address_state(address_state)

                address_state = state.get_address(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_get_address2(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                alice_address = alice_xmss.address
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

                transfer_token_transaction = TransferTokenTransaction.create(token_txhash=token_transaction.txhash,
                                                                             addrs_to=[alice_xmss.address],
                                                                             amounts=[100000000],
                                                                             fee=1,
                                                                             xmss_pk=bob_xmss.pk)

                state.update_token_metadata(transfer_token_transaction)

                token_metadata = state.get_token_metadata(token_transaction.txhash)
                self.assertEqual(len(token_metadata.transfer_token_tx_hashes), 2)
                self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)
                self.assertEqual(token_metadata.transfer_token_tx_hashes[1], transfer_token_transaction.txhash)

    def test_block_size_limit(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)
                self.assertEqual(state.get_block_size_limit(blocks[-1]), 1048576)

    def test_block_metadata(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)

                for block in blocks:
                    state.put_block_metadata(block.headerhash, BlockMetadata(), None)

                for block in blocks:
                    self.assertEqual(state.get_block_metadata(block.headerhash).to_json(), b'{}')

    def test_address_list(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)

                for block in blocks:
                    self.assertIn(alice_xmss.address, State.prepare_address_list(block))

    def test_get_block_datapoint(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)
                for i in range(1, 20):
                    datapoint = state.get_block_datapoint(blocks[i].headerhash)
                    self.assertEqual(datapoint.difficulty, "0")
                    self.assertEqual(datapoint.timestamp, 1615270948)
                    self.assertEqual(datapoint.header_hash, blocks[i].headerhash)
                    self.assertEqual(datapoint.header_hash_prev, blocks[i - 1].headerhash)

    def test_address_state(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)

                for i, block in enumerate(blocks):
                    self.assertIn(alice_xmss.address, state.prepare_address_list(block))
                    address_state = state.get_state(block.headerhash, state.prepare_address_list(block))
                    self.assertIn(alice_xmss.address, address_state.keys())
                    self.assertEqual(address_state[config.dev.coinbase_address].nonce, i + 1)
                    with self.assertRaises(Exception):
                        state.set_addresses_state({"state": 'test'}, 0)

    @set_default_balance_size()
    def test_basic_state_funcs(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                self.assertEqual(state.nonce(alice_xmss.address), 0)
                self.assertNotEqual(state.balance(alice_xmss.address), 0)
                self.assertTrue(state.address_used(alice_xmss.address))
                self.assertEqual(state.return_all_addresses(), [])
                batch = state.get_batch()
                self.assertIsNotNone(batch)
                state.write_batch(batch)
                self.assertEqual(state.total_coin_supply(), 0)

    def test_state_block_map(self):
        with set_data_dir('no_data'):
            with State() as state:
                bm = qrl_pb2.BlockNumberMapping()
                state.put_block_number_mapping(b"0", bm, None)
                read_bm = state.get_block_number_mapping(b"0")
                self.assertEqual(type(bm), type(read_bm))
                self.assertIsNone(state.get_block_by_number(b"4"))

    def test_state_mainchain(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)
                address_set = state.prepare_address_list(blocks[-1])
                m = state.get_state_mainchain(address_set)
                state.update_mainchain_state(m, 20, blocks[-1].headerhash)
                self.assertIsNotNone(m)
                self.assertTrue(len(m) > 0)
                state.update_mainchain_height(5, None)
                self.assertEqual(state.get_mainchain_height(), 5)
                self.assertIsNotNone(state.get_ephemeral_metadata(b"0"))

    def test_state_tx(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)

                self.assertEqual(state.get_last_txs(), [])
                state.update_last_tx(blocks[-1], None)
                self.assertEqual(state.get_txn_count(alice_xmss.address), 0)

    def test_state_loader(self):
        with set_data_dir('no_data'):
            alice_xmss = get_alice_xmss()
            state_loader = StateLoader(b'current_', db.DB())
            self.assertEqual(state_loader.total_coin_supply, 0)
            state_loader.update_total_coin_supply(100)
            self.assertEqual(state_loader.total_coin_supply, 100)
            self.assertIsNone(state_loader.get_address(alice_xmss.address))
            state_loader.add_address(alice_xmss.address)
            self.assertEqual(state_loader._data.addresses, [alice_xmss.address])

    def test_state_object(self):
        with set_data_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)

                self.assertEqual(state.state_objects.total_coin_supply(), 0)
                self.assertEqual(state.state_objects.state_loaders, [])
                state.state_objects.append_state_loader(StateLoader(b'current_', state._db))
                self.assertIsNotNone(state.state_objects.get_state_loader_by_index(0))
                state.state_objects.destroy_state_loader(0)
                self.assertEqual(state.state_objects.state_loaders, [])

                self.assertIsNone(state.state_objects.get(b'current'))
                state.state_objects.push(blocks[-1].headerhash, None)
                self.assertEqual(len(state.state_objects.state_loaders), 1)

                loader = state.state_objects.state_loaders[0]
                loader.increase_txn_count(state._db, b'', 0, alice_xmss.address)
                self.assertEqual(loader.get_txn_count(state._db, b'', alice_xmss.address), 1)
                self.assertEqual(loader.get_last_txs(state._db, b''), [])
                loader.commit(StateLoader(b'current_', state._db))
                loader.update_last_tx(blocks[-1], None)
                loader.commit(StateLoader(b'current_', state._db))

                state.state_objects.update_current_state({alice_xmss.address: state._get_address_state(alice_xmss.address)})
                self.assertEqual(state.state_objects.get_txn_count(alice_xmss.address), 1)
                state.state_objects.increase_txn_count(alice_xmss.address)
                self.assertEqual(state.state_objects.get_last_txs(), [])
                state.state_objects.update_last_tx(blocks[-1], None)
                state.state_objects.update_tx_metadata(blocks[-1], None)
                self.assertEqual(state.state_objects.get_last_txs(), [])
                state.state_objects.destroy_fork_states(blocks[-1].block_number, blocks[-1].headerhash)
                state.state_objects.destroy_current_state(None)
                self.assertIsNone(state.state_objects.get(b'current'))

    def test_destroy_current_state(self):
        with set_data_dir('no_data'):
            with State() as state:
                genesis_block = GenesisBlock()
                state.put_block(genesis_block, None)
                dummy_state = StateLoader(bin2hstr(genesis_block.headerhash).encode(), state._db)
                state.state_objects.append_state_loader(dummy_state)

                alice_xmss = get_alice_xmss()
                alice_address_state = AddressState.get_default(alice_xmss.address)

                for _ in range(10):
                    alice_address_state.increase_nonce()

                addresses_state = {alice_xmss.address: alice_address_state}
                state.state_objects.update_current_state(addresses_state)
                alice_address_state2 = state.get_address(alice_xmss.address)
                self.assertEqual(alice_address_state.nonce, alice_address_state2.nonce)

                state.state_objects.destroy_current_state(None)
                alice_address_state2 = state.get_address(alice_xmss.address)
                self.assertEqual(0, alice_address_state2.nonce)
