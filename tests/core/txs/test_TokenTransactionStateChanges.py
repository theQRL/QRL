from unittest import TestCase

from mock import Mock

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.generated import qrl_pb2
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss, set_qrl_dir

logger.initialize_default()


class TestTokenTransactionStateChanges(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        alice_address_state.pbdata.balance = 100
        self.addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: OptimizedAddressState.get_default(self.bob.address)
        }

        self.params = {
            "symbol": b'QRL',
            "name": b'Quantum Resistant Ledger',
            "owner": self.alice.address,
            "decimals": 15,
            "initial_balances": [],
            "fee": 1,
            "xmss_pk": self.alice.pk
        }

        self.unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

    def test_apply_token_txn(self):
        """
        Alice creates a token. Obviously, she gives herself some of this token.
        But she also gives Bob some tokens too.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=2000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        # According to the State, Alice has 100 coins, and Bob has 0 coins.
        # After applying the Transaction, Alice and Bob should have 1000 tokens, and Alice's balance should be 99.
        # AddressState.transaction_hashes now also reference the TokenTransaction that created the Tokens.
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        tx.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)

        self.assertEqual(2, len(state_container.paginated_tx_hash.key_value))

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertEqual(2, len(state_container.tokens.data))
        self.assertIn((self.alice.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(1000, state_container.tokens.data[(self.alice.address, tx.txhash)].balance)
        self.assertIn((self.bob.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(2000, state_container.tokens.data[(self.bob.address, tx.txhash)].balance)

    def test_apply_state_changes_owner_not_in_address_state(self):
        """
        In this case, Alice didn't give herself any tokens. How generous! She gave them all to Bob.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)

        # Signing the TX also generates the txhash, which we need to generate the AddressState properly.
        addresses_state = dict(self.addresses_state)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        tx.apply(self.state, state_container)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)

        self.assertEqual(2, len(state_container.paginated_tx_hash.key_value))

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertEqual(1, len(state_container.tokens.data))
        self.assertIn((self.bob.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(1000, state_container.tokens.data[(self.bob.address, tx.txhash)].balance)

    def test_apply_token_txn_signed_by_slave_xmss(self):
        """
        Alice creates a token, gives herself and Bob some tokens.
        But she uses a XMSS slave to sign it.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=2000)]
        slave = get_slave_xmss()
        self.params["initial_balances"] = initial_balances
        self.params["xmss_pk"] = slave.pk
        self.params["master_addr"] = self.alice.address
        tx = TokenTransaction.create(**self.params)
        tx.sign(slave)

        # Now that we have the Slave XMSS address, we should add it to AddressState so that apply_state_changes()
        # can do something with it
        addresses_state = dict(self.addresses_state)
        addresses_state[slave.address] = OptimizedAddressState.get_default(slave.address)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        tx.apply(self.state, state_container)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(3, len(state_container.paginated_tx_hash.key_value))

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(slave.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertEqual(2, len(state_container.tokens.data))
        self.assertIn((self.bob.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(1000, state_container.tokens.data[(self.alice.address, tx.txhash)].balance)
        self.assertEqual(2000, state_container.tokens.data[(self.bob.address, tx.txhash)].balance)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(slave.address, 0))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.bob.address, 0))

    def test_revert_token_txn(self):
        """
        Same setup as in test_apply_state_changes(). This time though, the changes have already been applied,
        and we would like to roll them back.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=2000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)
        # Apply the changes!
        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        addresses_state[self.alice.address].pbdata.balance = 100
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        # After applying the Transaction, it should be as if Alice had never created the tokens in the first place.
        tx.apply(self.state, state_container)
        tx.revert(self.state, state_container)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)

        self.assertEqual(2, len(state_container.paginated_tx_hash.key_value))

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertEqual(2, len(state_container.tokens.data))
        self.assertIn((self.alice.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(0, state_container.tokens.data[(self.alice.address, tx.txhash)].balance)
        self.assertIn((self.bob.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(0, state_container.tokens.data[(self.bob.address, tx.txhash)].balance)
        self.assertEqual(0, addresses_state[self.alice.address].nonce)

    def test_revert_token_txn_owner_not_in_address_state(self):
        """
        In this case, Alice didn't give herself any tokens. How generous! She gave them all to Bob.
        But we want to revert this.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)

        addresses_state = dict(self.addresses_state)
        addresses_state[self.alice.address].pbdata.balance = 100
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        state_container.paginated_bitfield.set_ots_key(addresses_state, self.alice.address, 0)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        tx.apply(self.state, state_container)
        tx.revert(self.state, state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)

        self.assertEqual(2, len(state_container.paginated_tx_hash.key_value))

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertEqual(1, len(state_container.tokens.data))
        self.assertIn((self.bob.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(0, state_container.tokens.data[(self.bob.address, tx.txhash)].balance)

    def test_revert_token_txn_signed_by_slave_xmss(self):
        """
        Alice creates a token, gives herself and Bob some tokens.
        But she uses a XMSS slave to sign it.
        Can we undo it?
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=2000)]
        slave = get_slave_xmss()
        self.params["initial_balances"] = initial_balances
        self.params["xmss_pk"] = slave.pk
        self.params["master_addr"] = self.alice.address
        tx = TokenTransaction.create(**self.params)
        tx.sign(slave)

        # Now that we have the Slave XMSS address, we should add it to AddressState so that apply_state_changes()
        # can do something with it
        addresses_state = dict(self.addresses_state)
        addresses_state[slave.address] = OptimizedAddressState.get_default(slave.address)
        addresses_state[slave.address].pbdata.nonce = 1

        # Also, update the AddressStates manually!
        addresses_state[self.alice.address].pbdata.balance = 100
        addresses_state[self.bob.address].pbdata.balance = 0
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        state_container.paginated_bitfield.set_ots_key(addresses_state, slave.address, 0)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(slave.address, 0))
        tx.apply(self.state, state_container)
        tx.revert(self.state, state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(slave.address, 0))

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(3, len(state_container.paginated_tx_hash.key_value))

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(slave.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertEqual(2, len(state_container.tokens.data))
        self.assertIn((self.alice.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(0, state_container.tokens.data[(self.alice.address, tx.txhash)].balance)
        self.assertIn((self.bob.address, tx.txhash), state_container.tokens.data)
        self.assertEqual(0, state_container.tokens.data[(self.bob.address, tx.txhash)].balance)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.bob.address, 0))

    def test_validate_tx(self):
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        slave = get_slave_xmss()
        self.params["initial_balances"] = initial_balances
        self.params["xmss_pk"] = slave.pk
        self.params["master_addr"] = self.alice.address
        tx = TokenTransaction.create(**self.params)
        tx.sign(slave)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()
