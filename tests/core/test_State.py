# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
import mock
from mock import MagicMock

from pyqrllib.pyqrllib import sha2_256
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.TokenMetadata import TokenMetadata
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.generated import qrl_pb2

from tests.misc.helper import set_qrl_dir, get_alice_xmss, get_bob_xmss, get_token_transaction, get_some_address, \
    replacement_getTime

logger.initialize_default()


def gen_blocks(block_count, state, miner_address):
    blocks = []
    block = None
    with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
        time_mock.return_value = 1615270948
        addresses_state = dict()
        for i in range(0, block_count):
            if i == 0:
                block = GenesisBlock()
                for genesis_balance in GenesisBlock().genesis_balance:
                    bytes_addr = genesis_balance.address
                    addresses_state[bytes_addr] = AddressState.get_default(bytes_addr)
                    addresses_state[bytes_addr]._data.balance = genesis_balance.balance
            else:
                block = Block.create(block_number=i,
                                     prev_headerhash=block.headerhash,
                                     prev_timestamp=block.timestamp,
                                     transactions=[],
                                     miner_address=miner_address)
                addresses_set = state.prepare_address_list(block)
                for address in addresses_set:
                    addresses_state[address] = state.get_address_state(address)
                for tx_protobuf in block.transactions:
                    tx = Transaction.from_pbdata(tx_protobuf)
                    tx.apply_state_changes(addresses_state)

                block.set_nonces(10, 0)
            blocks.append(block)

            metadata = BlockMetadata()
            metadata.set_block_difficulty(StringToUInt256('256'))
            state.put_block_metadata(block.headerhash, metadata, None)

            state.put_block(block, None)
            bm = qrl_pb2.BlockNumberMapping(headerhash=block.headerhash,
                                            prev_headerhash=block.prev_headerhash)

            state.put_block_number_mapping(block.block_number, bm, None)
            state.update_mainchain_height(block.block_number, None)
            state.put_addresses_state(addresses_state)

    return blocks


@mock.patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestState(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestState, self).__init__(*args, **kwargs)

    def test_create_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

    def test_release_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

    def test_get_address_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                alice_address = alice_xmss.address
                address_state = state.get_address_state(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

                alice_address = bytearray(alice_xmss.address)
                with self.assertRaises(TypeError):
                    state.get_address_state(alice_address)

                alice_address = alice_xmss.address
                address_state = state.get_address_state(alice_address)
                addresses_state = {
                    alice_address: address_state
                }
                self.assertTrue(isinstance(address_state.address, bytes))
                state.put_addresses_state(addresses_state)

                address_state = state.get_address_state(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_get_all_address_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                addresses_state = state.get_all_address_state()
                self.assertEqual(len(addresses_state), 0)

                alice_xmss = get_alice_xmss()
                alice_address = alice_xmss.address
                address_state = state.get_address_state(alice_address)
                addresses_state = {
                    alice_address: address_state
                }
                self.assertTrue(isinstance(address_state.address, bytes))
                state.put_addresses_state(addresses_state)

                addresses_state = state.get_all_address_state()
                self.assertEqual(len(addresses_state), 1)

                bob_xmss = get_bob_xmss()
                bob_address = bob_xmss.address
                address_state = state.get_address_state(bob_address)
                addresses_state = {
                    bob_address: address_state
                }
                self.assertTrue(isinstance(address_state.address, bytes))
                state.put_addresses_state(addresses_state)

                addresses_state = state.get_all_address_state()
                self.assertEqual(len(addresses_state), 2)

    def test_basic_state_funcs(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                self.assertTrue(state.get_address_is_used(alice_xmss.address))
                self.assertEqual(state._return_all_addresses(), [])
                batch = state.batch
                self.assertIsNotNone(batch)
                state.write_batch(batch)
                self.assertEqual(state.total_coin_supply, 0)

    def test_get_address_nonce(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                self.assertEqual(state.get_address_nonce(alice_xmss.address), 0)

    def test_get_address_balance(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                self.assertEqual(state.get_address_balance(alice_xmss.address), 0)

    def test_get_address2(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                alice_address = alice_xmss.address
                address_state = state.get_address_state(alice_address)
                addresses_state = {
                    alice_address: address_state
                }
                self.assertTrue(isinstance(address_state.address, bytes))
                state.put_addresses_state(addresses_state)
                address_state = state.get_address_state(alice_address)
                self.assertTrue(isinstance(address_state.address, bytes))

    def test_create_token_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                token_transaction = get_token_transaction(alice_xmss, bob_xmss)
                state.create_token_metadata(token_transaction)

                token_metadata = state.get_token_metadata(token_transaction.txhash)
                self.assertEqual(token_metadata.token_txhash, token_transaction.txhash)
                self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)

    def test_update_token_metadata(self):
        with set_qrl_dir('no_data'):
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

    def test_get_token_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                token_txhash = bytes(sha2_256(b'alpha'))
                token_metadata = TokenMetadata.create(token_txhash,
                                                      [bytes(sha2_256(b'delta')),
                                                       bytes(sha2_256(b'gamma'))])
                state._db.get_raw = MagicMock(return_value=token_metadata.serialize())
                self.assertEqual(state.get_token_metadata(token_txhash).to_json(),
                                 token_metadata.to_json())

    def test_remove_transfer_token_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                token_transaction = get_token_transaction(alice_xmss, bob_xmss)
                state.create_token_metadata(token_transaction)

                transfer_token = TransferTokenTransaction.create(token_txhash=token_transaction.txhash,
                                                                 addrs_to=[alice_xmss.address],
                                                                 amounts=[100000000],
                                                                 fee=1,
                                                                 xmss_pk=bob_xmss.pk)
                transfer_token.sign(alice_xmss)

                state.update_token_metadata(transfer_token)
                token_metadata = state.get_token_metadata(transfer_token.token_txhash)
                self.assertIn(transfer_token.txhash,
                              token_metadata.transfer_token_tx_hashes)

                state.remove_transfer_token_metadata(transfer_token)
                token_metadata = state.get_token_metadata(transfer_token.token_txhash)
                self.assertNotIn(transfer_token.txhash,
                                 token_metadata.transfer_token_tx_hashes)

    def test_remove_token_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                bob_xmss = get_bob_xmss()

                token_tx = get_token_transaction(alice_xmss, bob_xmss)
                state.create_token_metadata(token_tx)

                token_metadata = state.get_token_metadata(token_tx.txhash)
                self.assertEqual(token_metadata.token_txhash, token_tx.txhash)
                state.remove_token_metadata(token_tx)
                self.assertIsNone(state.get_token_metadata(token_tx.txhash))

    def test_address_used(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                self.assertTrue(state.get_address_is_used(alice_xmss.address))

    def test_return_all_addresses(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state._return_all_addresses(), [])

    def test_get_batch(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state.batch)

    def test_write_batch(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                batch = state.batch
                block = Block.create(block_number=10,
                                     prev_headerhash=b'aa',
                                     prev_timestamp=10,
                                     transactions=[],
                                     miner_address=b'aa')
                state.put_block(block, batch)
                self.assertIsNone(state.get_block(block.headerhash))
                state.write_batch(batch)
                block2 = state.get_block(block.headerhash)
                self.assertEqual(block.headerhash, block2.headerhash)

    def test_update_total_coin_supply(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state.total_coin_supply, 0)
                state._update_total_coin_supply(100)
                self.assertEqual(state.total_coin_supply, 100)

    def test_total_coin_supply(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state.total_coin_supply, 0)

    def test_get_measurement(self):
        def block(headerhash):
            nth_block = Block()
            if headerhash == b'test_block_1':
                nth_block.blockheader._data.timestamp_seconds = 50000
            elif headerhash == b'test_block_2':
                nth_block.blockheader._data.timestamp_seconds = 80000
            elif headerhash == b'test_block_3':
                nth_block.blockheader._data.timestamp_seconds = 90000
            return nth_block

        with set_qrl_dir('no_data'):
            with State() as state:
                parent_metadata = BlockMetadata.create(block_difficulty=b'\x00' * 32,
                                                       cumulative_difficulty=b'\x00' * 32,
                                                       child_headerhashes=[])

                measurement = state.get_measurement(block_timestamp=100000,
                                                    parent_headerhash=b'',
                                                    parent_metadata=parent_metadata)

                # Test Case, when count_headerhashes equals 0
                self.assertEqual(measurement, config.dev.mining_setpoint_blocktime)

                state.get_block = MagicMock(side_effect=block)
                parent_metadata.update_last_headerhashes([], b'test_block_1')

                measurement = state.get_measurement(block_timestamp=100000,
                                                    parent_headerhash=b'test_block_1',
                                                    parent_metadata=parent_metadata)

                # Test Case, when count_headerhashes equals 1
                self.assertEqual(measurement,
                                 (100000 - 50000 + config.dev.mining_setpoint_blocktime) // 2)

                parent_metadata.update_last_headerhashes([b'test_block_1'], b'test_block_2')

                measurement = state.get_measurement(block_timestamp=100000,
                                                    parent_headerhash=b'test_block_2',
                                                    parent_metadata=parent_metadata)

                # Test Case, when count_headerhashes is greater than 1
                # but less than config.dev.N_measurement
                self.assertEqual(measurement,
                                 (100000 - 80000 + config.dev.mining_setpoint_blocktime) // 2)

                parent_metadata.update_last_headerhashes([b'test_block_3'] * config.dev.N_measurement,
                                                         b'test_block_2')

                measurement = state.get_measurement(block_timestamp=100000,
                                                    parent_headerhash=b'test_block_2',
                                                    parent_metadata=parent_metadata)

                # Test Case, when count_headerhashes is greater than config.dev.N_measurement
                self.assertEqual(measurement,
                                 (100000 - 90000) // config.dev.N_measurement)

    def test_delete(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                block = Block()
                state.put_block(block, None)
                block1 = state.get_block(block.headerhash)
                self.assertEqual(block.serialize(), block1.serialize())
                state._delete(block.headerhash, None)
                self.assertIsNone(state.get_block(block.headerhash))

    def test_get_block_size_limit(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)
                self.assertEqual(state.get_block_size_limit(blocks[-1]), 1048576)

    def test_put_block_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                block_metadata = BlockMetadata.create()
                block_metadata.update_last_headerhashes([b'test1', b'test2'], b'test3')

                state.put_block_metadata(b'block_headerhash', block_metadata, None)
                state.put_block_metadata(b'block_headerhash2', BlockMetadata.create(), None)

                self.assertEqual(state.get_block_metadata(b'block_headerhash').to_json(),
                                 block_metadata.to_json())

                expected_json = b'{\n  "blockDifficulty": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",\n  ' \
                                b'"cumulativeDifficulty": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="\n}'

                self.assertEqual(state.get_block_metadata(b'block_headerhash2').to_json(),
                                 expected_json)

    def test_get_block_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNone(state.get_block_metadata(b'test1'))
                state.put_block_metadata(b'block_headerhash2', BlockMetadata.create(), None)

                tmp_json = state.get_block_metadata(b'block_headerhash2').to_json()

                expected_json = b'{\n  "blockDifficulty": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",\n  ' \
                                b'"cumulativeDifficulty": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="\n}'

                self.assertEqual(tmp_json, expected_json)

    def test_prepare_address_list(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                block = Block.create(block_number=10,
                                     prev_headerhash=b'',
                                     prev_timestamp=10,
                                     transactions=[],
                                     miner_address=get_some_address(1))
                # Test Case: without any transactions of block
                self.assertEqual(state.prepare_address_list(block),
                                 {config.dev.coinbase_address, get_some_address(1)})

                alice_xmss = get_alice_xmss()
                block = Block.create(block_number=10,
                                     prev_headerhash=b'',
                                     prev_timestamp=10,
                                     transactions=[TransferTransaction.create(addrs_to=[get_some_address(2),
                                                                                        get_some_address(3)],
                                                                              amounts=[100, 100],
                                                                              fee=0,
                                                                              xmss_pk=alice_xmss.pk)],
                                     miner_address=get_some_address(1))

                # Test Case, with one Transaction
                self.assertEqual(state.prepare_address_list(block),
                                 {config.dev.coinbase_address,
                                  get_some_address(1),
                                  get_some_address(2),
                                  get_some_address(3),
                                  alice_xmss.address})

    def test_put_addresses_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                alice_state = AddressState.get_default(alice_xmss.address)
                addresses_state = {
                    alice_state.address: alice_state,
                    b'test1': AddressState.get_default(b'test1')
                }
                state.put_addresses_state(addresses_state, None)
                alice_state2 = state.get_address_state(alice_xmss.address)
                self.assertEqual(alice_state.serialize(), alice_state2.serialize())
                test_state = state.get_address_state(b'test1')
                self.assertEqual(test_state.serialize(), AddressState.get_default(b'test1').serialize())

    def test_get_state_mainchain(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                alice_state = AddressState.get_default(alice_xmss.address)
                alice_state.increase_nonce()
                alice_state.balance += 1000
                addresses_state = {
                    alice_state.address: alice_state,
                    b'test1': AddressState.get_default(b'test1')
                }
                state.put_addresses_state(addresses_state, None)
                addresses_state1 = state.get_state_mainchain({alice_state.address, b'test1'})

                self.assertEqual(addresses_state[alice_state.address].serialize(),
                                 addresses_state1[alice_state.address].serialize())
                self.assertEqual(addresses_state[b'test1'].serialize(),
                                 addresses_state1[b'test1'].serialize())

    def test_get_block_datapoint(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                # Test Case: When block not found
                self.assertIsNone(state.get_block_datapoint(b'test'))

                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)
                for i in range(1, 20):
                    datapoint = state.get_block_datapoint(blocks[i].headerhash)
                    self.assertEqual(datapoint.difficulty, "256")
                    self.assertEqual(datapoint.timestamp, 1615270947 + i)
                    self.assertEqual(datapoint.header_hash, blocks[i].headerhash)
                    self.assertEqual(datapoint.header_hash_prev, blocks[i - 1].headerhash)

    def test_put_block_number_mapping(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                bm = qrl_pb2.BlockNumberMapping()
                state.put_block_number_mapping(0, bm, None)
                read_bm = state.get_block_number_mapping(0)
                self.assertEqual(bm.SerializeToString(),
                                 read_bm.SerializeToString())
                self.assertIsNone(state.get_block_by_number(4))

    def test_get_block_number_mapping(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNone(state.get_block_number_mapping(0))
                bm = qrl_pb2.BlockNumberMapping()
                state.put_block_number_mapping(0, bm, None)
                read_bm = state.get_block_number_mapping(0)
                self.assertEqual(bm.SerializeToString(),
                                 read_bm.SerializeToString())

    def test_get_block_by_number(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                bm = qrl_pb2.BlockNumberMapping()
                state.put_block_number_mapping(0, bm, None)
                self.assertIsNone(state.get_block_by_number(4))

    def test_update_mainchain_height(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                state.update_mainchain_height(5, None)
                self.assertEqual(state.get_mainchain_height(), 5)

    def test_get_mainchain_height(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                # Test Case: Check default value
                self.assertEqual(state.get_mainchain_height(), -1)

                state.update_mainchain_height(15, None)
                self.assertEqual(state.get_mainchain_height(), 15)

                state.update_mainchain_height(5, None)
                self.assertEqual(state.get_mainchain_height(), 5)

    def test_last_block(self):
        with set_qrl_dir('no_data'):
            def get_block_by_number(block_number):
                block = Block()
                block.blockheader._data.block_number = block_number
                return block

            with State() as state:
                self.assertIsNone(state.last_block)
                state.get_block_by_number = MagicMock(side_effect=get_block_by_number)

                state.update_mainchain_height(10, None)
                self.assertEqual(state.last_block.block_number, 10)

                state.update_mainchain_height(1, None)
                self.assertEqual(state.last_block.block_number, 1)

    def test_update_last_tx(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                # Test Case: When there is no last txns
                self.assertEqual(state.get_last_txs(), [])

                block = Block()
                tx1 = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                 amounts=[1, 2],
                                                 fee=0,
                                                 xmss_pk=alice_xmss.pk)
                block._data.transactions.extend([tx1.pbdata])
                state._update_last_tx(block, None)
                last_txns = state.get_last_txs()

                # Test Case: When there is only 1 last txns
                self.assertEqual(len(last_txns), 1)
                self.assertEqual(last_txns[0].to_json(), tx1.to_json())

                block = Block()
                tx2 = TransferTransaction.create(addrs_to=[get_some_address(2), get_some_address(3)],
                                                 amounts=[1, 2],
                                                 fee=0,
                                                 xmss_pk=alice_xmss.pk)

                tx3 = TransferTransaction.create(addrs_to=[get_some_address(4), get_some_address(5)],
                                                 amounts=[1, 2],
                                                 fee=0,
                                                 xmss_pk=alice_xmss.pk)
                block._data.transactions.extend([tx2.pbdata, tx3.pbdata])
                state._update_last_tx(block, None)
                last_txns = state.get_last_txs()

                # Test Case: When there are 3 last txns
                self.assertEqual(len(last_txns), 3)
                self.assertEqual(last_txns[0].to_json(),
                                 tx3.to_json())
                self.assertEqual(last_txns[1].to_json(),
                                 tx2.to_json())
                self.assertEqual(last_txns[2].to_json(),
                                 tx1.to_json())

    def test_get_last_txs(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state.get_last_txs(), [])

                alice_xmss = get_alice_xmss()
                block = Block()
                tx1 = TransferTransaction.create(addrs_to=[get_some_address(0), get_some_address(1)],
                                                 amounts=[1, 2],
                                                 fee=0,
                                                 xmss_pk=alice_xmss.pk)
                block._data.transactions.extend([tx1.pbdata])
                state._update_last_tx(block, None)
                last_txns = state.get_last_txs()

                # Test Case: When there is only 1 last txns
                self.assertEqual(len(last_txns), 1)
                self.assertEqual(last_txns[0].to_json(), tx1.to_json())

    def test_remove_last_tx(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                # Test Case: When there is no last txns
                self.assertEqual(state.get_last_txs(), [])

                alice_xmss = get_alice_xmss()

                block = Block()
                tx1 = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                 amounts=[1, 2],
                                                 fee=0,
                                                 xmss_pk=alice_xmss.pk)
                block._data.transactions.extend([tx1.pbdata])
                state._update_last_tx(block, None)
                last_txns = state.get_last_txs()

                self.assertEqual(last_txns[0].to_json(), tx1.to_json())

                state._remove_last_tx(block, None)
                last_txns = state.get_last_txs()
                self.assertEqual(last_txns, [])

    def test_rollback_tx_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()

                tx1 = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                 amounts=[1, 2],
                                                 fee=0,
                                                 xmss_pk=alice_xmss.pk)

                block = Block.create(block_number=5,
                                     prev_headerhash=b'',
                                     prev_timestamp=10,
                                     transactions=[tx1],
                                     miner_address=b'')

                state.update_tx_metadata(block=block,
                                         batch=None)

                tx_metadata = state.get_tx_metadata(tx1.txhash)

                self.assertEqual(tx_metadata[0].to_json(), tx1.to_json())
                state.rollback_tx_metadata(block, None)
                self.assertIsNone(state.get_tx_metadata(tx1.txhash))

    def test_update_tx_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                alice_xmss = get_alice_xmss()
                tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                amounts=[1, 2],
                                                fee=0,
                                                xmss_pk=alice_xmss.pk)
                block_number = 5
                state.put_tx_metadata(tx, block_number, 10000, None)

                tx_metadata = state.get_tx_metadata(tx.txhash)
                self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
                self.assertEqual(tx_metadata[1], block_number)

    def test_remove_tx_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNone(state.get_tx_metadata(b'test1'))

                alice_xmss = get_alice_xmss()
                tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                amounts=[1, 2],
                                                fee=0,
                                                xmss_pk=alice_xmss.pk)
                block_number = 5
                state.put_tx_metadata(tx, block_number, 10000, None)

                tx_metadata = state.get_tx_metadata(tx.txhash)
                self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
                self.assertEqual(tx_metadata[1], block_number)

                state.remove_tx_metadata(tx, None)
                self.assertIsNone(state.get_tx_metadata(tx.txhash))

    def test_put_tx_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNone(state.get_tx_metadata(b'test1'))

                alice_xmss = get_alice_xmss()
                tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                amounts=[1, 2],
                                                fee=0,
                                                xmss_pk=alice_xmss.pk)
                block_number = 5
                state.put_tx_metadata(tx, block_number, 10000, None)

                tx_metadata = state.get_tx_metadata(tx.txhash)
                self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
                self.assertEqual(tx_metadata[1], block_number)

    def test_get_tx_metadata(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNone(state.get_tx_metadata(b'test1'))

                alice_xmss = get_alice_xmss()
                tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                                amounts=[1, 2],
                                                fee=0,
                                                xmss_pk=alice_xmss.pk)
                block_number = 5
                timestamp = 10000
                state.put_tx_metadata(tx, block_number, timestamp, None)

                tx_metadata = state.get_tx_metadata(tx.txhash)
                self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
                self.assertEqual(tx_metadata[1], block_number)

    def test_increase_txn_count(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state.get_txn_count(b'q1'), 0)

                state._increase_txn_count(0, b'q1')
                self.assertEqual(state.get_txn_count(b'q1'), 1)

                state._increase_txn_count(5, b'q1')
                self.assertEqual(state.get_txn_count(b'q1'), 6)

    def test_decrease_txn_count(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state.get_txn_count(b'q1'), 0)

                with self.assertRaises(ValueError):
                    state._decrease_txn_count(0, b'q1')

                state._decrease_txn_count(5, b'q1')
                self.assertEqual(state.get_txn_count(b'q1'), 4)

    def test_get_txn_count(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertEqual(state.get_txn_count(b'q1'), 0)

                state._increase_txn_count(10, b'q1')
                self.assertEqual(state.get_txn_count(b'q1'), 11)
