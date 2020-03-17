from unittest import TestCase

from mock import Mock

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.generated.qrl_pb2 import TokenBalance
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss, set_qrl_dir

logger.initialize_default()


class TestTransferTokenTransactionStateChanges(TestCase):
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
            "token_txhash": b'I declare the TEST token',
            "addrs_to": [self.bob.address],
            "amounts": [100],
            "fee": 1,
            "xmss_pk": self.alice.pk
        }

        self.unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

    def test_apply_transfer_token_txn(self):
        """
        Alice has 1000 tokens and 100 QRL, Bob has none. Alice sends some tokens to Bob.
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=150)
        tokens.data[(self.bob.address, tx.token_txhash)] = TokenBalance(balance=0)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        tx.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)

        self.assertEqual(tokens.data[(self.alice.address, tx.token_txhash)].balance, 50)
        self.assertEqual(tokens.data[(self.bob.address, tx.token_txhash)].balance, 100)

    def test_apply_transfer_token_txn_multi_send(self):
        """
        Alice has 1000 tokens and 100 QRL, Bob and Slave have none. Alice sends some tokens to Bob and Slave.
        """
        slave = get_slave_xmss()
        params = self.params.copy()
        params["addrs_to"] = [self.bob.address, slave.address]
        params["amounts"] = [100, 100]

        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        addresses_state[slave.address] = OptimizedAddressState.get_default(slave.address)
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=200)
        tokens.data[(self.bob.address, tx.token_txhash)] = TokenBalance(balance=0)
        tokens.data[(slave.address, tx.token_txhash)] = TokenBalance(balance=0)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        tx.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        self.assertEqual(addresses_state[slave.address].balance, 0)

        self.assertEqual(tokens.data[(self.alice.address, tx.token_txhash)].balance, 0)
        self.assertEqual(tokens.data[(self.bob.address, tx.token_txhash)].balance, 100)
        self.assertEqual(tokens.data[(slave.address, tx.token_txhash)].balance, 100)

    def test_apply_transfer_token_txn_send_tokens_to_self(self):
        """
        Alice has 1000 tokens and 100 QRL. She sends some tokens to herself. What happens next?
        """
        self.params["addrs_to"] = [self.alice.address]
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=100)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))
        tx.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, 0))

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(tokens.data[(self.alice.address, tx.token_txhash)].balance, 100)

    def test_revert_transfer_token_txn(self):
        """
        Alice has 1000 tokens and 100 QRL, Bob has none. Alice sends some tokens to Bob.
        Let's undo this.
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        addresses_state[self.alice.address].pbdata.balance = 100
        addresses_state[self.bob.address].pbdata.balance = 0
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=1000)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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

        self.assertEqual(tokens.data[(self.alice.address, tx.token_txhash)].balance, 1000)
        self.assertEqual(tokens.data[(self.bob.address, tx.token_txhash)].balance, 0)

    def test_revert_transfer_token_txn_multi_send(self):
        """
        Alice has 1100 tokens and 100 QRL, Bob and Slave have none. Alice sends some tokens to Bob and Slave.
        Undo this.
        """
        slave = get_slave_xmss()
        self.params["addrs_to"] = [self.bob.address, slave.address]
        self.params["amounts"] = [100, 100]

        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        addresses_state[self.alice.address].pbdata.balance = 100
        addresses_state[self.bob.address].pbdata.balance = 0
        addresses_state[slave.address] = OptimizedAddressState.get_default(slave.address)
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=1100)

        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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
        self.assertEqual(addresses_state[slave.address].balance, 0)

        self.assertEqual(tokens.data[(self.alice.address, tx.token_txhash)].balance, 1100)
        self.assertEqual(tokens.data[(self.bob.address, tx.token_txhash)].balance, 0)
        self.assertEqual(tokens.data[(slave.address, tx.token_txhash)].balance, 0)

    def test_revert_transfer_token_txn_empty_addresses_state(self):
        """
        If we didn't have any AddressStates for the addresses involved in this test, do nothing
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=100)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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

        self.assertEqual(100, tokens.data[(self.alice.address, tx.token_txhash)].balance)
        self.assertEqual(0, tokens.data[(self.bob.address, tx.token_txhash)].balance)

    def test_revert_transfer_token_txn_send_tokens_to_self(self):
        """
        Alice has 1000 tokens and 100 QRL. She sends some tokens to herself.
        Can we undo this?
        """
        self.params["addrs_to"] = [self.alice.address]
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        addresses_state[self.alice.address].pbdata.balance = 100
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = TokenBalance(balance=100)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
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
        # Unfortunately importing mock.call results in some sort of ValueError so I can't check the arguments.
        self.assertEqual(tokens.data[(self.alice.address, tx.token_txhash)].balance, 100)
