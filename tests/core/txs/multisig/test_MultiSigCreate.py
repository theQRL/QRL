from unittest import TestCase

import simplejson as json

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.AddressState import AddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.txs.multisig.MultiSigCreate import MultiSigCreate
from tests.core.txs.testdata import test_json_MultiSigCreate
from qrl.generated.qrl_pb2 import SlaveMetadata
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir, set_hard_fork_block_number

logger.initialize_default()


class TestMultiSigCreate(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMultiSigCreate, self).__init__(*args, **kwargs)
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()
        self.random = get_alice_xmss(4)
        self.random_signer = get_bob_xmss(4)
        self.signatories = [self.alice.address, self.bob.address, self.random.address]
        self.weights = [20, 30, 10]
        self.threshold = 30

    def test_create(self):
        tx = MultiSigCreate.create(self.signatories,
                                   self.weights,
                                   self.threshold,
                                   0,
                                   self.random_signer.pk)
        self.assertIsInstance(tx, MultiSigCreate)

    def test_to_json(self):
        tx = MultiSigCreate.create(self.signatories,
                                   self.weights,
                                   self.threshold,
                                   0,
                                   self.random_signer.pk)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_MultiSigCreate), json.loads(txjson))

    def test_validate_custom(self):
        """
        MultiSigCreate _validate_custom() only checks if fee == 0
        """
        tx = MultiSigCreate.create(self.signatories,
                                   self.weights,
                                   self.threshold,
                                   0,
                                   self.random_signer.pk)
        del tx._data.multi_sig_create.signatories[-1]
        result = tx._validate_custom()
        self.assertFalse(result)

        tx._data.multi_sig_create.signatories.extend(self.signatories)
        result = tx._validate_custom()
        self.assertFalse(result)

        del tx._data.multi_sig_create.signatories[:]
        tx._data.multi_sig_create.signatories.extend(self.signatories)
        result = tx._validate_custom()
        self.assertTrue(result)

        tx._data.multi_sig_create.threshold = 1000
        result = tx._validate_custom()
        self.assertFalse(result)

    @set_hard_fork_block_number()
    def test_validate_extended(self):
        """
        CoinBase validate_extended() checks for
        1. valid coinbase address (the coinbase address must be config.dev.coinbase_address)
        2. valid addr_to
        then calls _validate_custom()
        """
        tx = MultiSigCreate.create(signatories=self.signatories,
                                   weights=self.weights,
                                   threshold=self.threshold,
                                   fee=5,
                                   xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5

        addresses_state = {
            self.alice.address: alice_address_state,
        }
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=None,
                                         batch=None)

        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        alice_address_state.pbdata.balance = 4
        result = tx._validate_extended(state_container)
        self.assertFalse(result)  # False due to insufficient balance to pay the txn fee

        alice_address_state.pbdata.balance = 6
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

    @set_hard_fork_block_number()
    def test_validate_all(self):
        tx = MultiSigCreate.create(signatories=self.signatories,
                                   weights=self.weights,
                                   threshold=self.threshold,
                                   fee=5,
                                   xmss_pk=self.random.pk,
                                   master_addr=self.alice.address)
        tx.sign(self.random)
        tx.pbdata.nonce = 1

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        random_address_state = OptimizedAddressState.get_default(address=self.random.address)

        addresses_state = {
            self.alice.address: alice_address_state,
            self.random.address: random_address_state,
        }
        slaves = Indexer(b'slave', None)
        slaves.data[(self.alice.address, self.random.pk)] = SlaveMetadata(access_type=0)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=slaves,
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=False,
                                         my_db=self.state._db,
                                         batch=None)

        result = tx.validate_all(state_container)
        self.assertTrue(result)

        tx.pbdata.nonce = 2
        result = tx.validate_all(state_container)
        self.assertFalse(result)  # False as nonce is invalid

    def test_apply_multi_sig_create_txn(self):
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.random.address: OptimizedAddressState.get_default(self.random.address),
            self.random_signer.address: OptimizedAddressState.get_default(self.random_signer.address),
        }
        addresses_state[self.random_signer.address].pbdata.balance = 200
        tx = MultiSigCreate.create(self.signatories,
                                   self.weights,
                                   self.threshold,
                                   1,
                                   self.random_signer.pk)
        tx.sign(self.random_signer)

        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.random_signer.address,
                                                                                            tx.ots_key))

        tx.apply(self.state, state_container)

        self.assertEqual(200 - tx.fee, addresses_state[self.random_signer.address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(self.random_signer.address, 1)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])
        for signatory_address in self.signatories:
            storage_key = state_container.paginated_tx_hash.generate_key(signatory_address, 1)
            self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.random_signer.address,
                                                                                           tx.ots_key))
        AddressState.put_addresses_state(self.state, addresses_state)
        multi_sig_addresses_state = MultiSigAddressState.get_multi_sig_address_state_by_address(
            self.state._db,
            MultiSigAddressState.generate_multi_sig_address(tx.txhash))

        self.assertEqual(self.signatories, multi_sig_addresses_state.signatories)
        self.assertEqual(self.weights, multi_sig_addresses_state.weights)
        self.assertEqual(self.threshold, multi_sig_addresses_state.threshold)

    def test_revert_multi_sig_create_txn(self):
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.random.address: OptimizedAddressState.get_default(self.random.address),
            self.random_signer.address: OptimizedAddressState.get_default(self.random_signer.address),
        }
        addresses_state[self.random_signer.address].pbdata.balance = 200
        tx = MultiSigCreate.create(self.signatories,
                                   self.weights,
                                   self.threshold,
                                   1,
                                   self.random_signer.pk)
        tx.sign(self.random_signer)

        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.random_signer.address,
                                                                                            tx.ots_key))

        tx.apply(self.state, state_container)

        self.assertEqual(200 - tx.fee, addresses_state[self.random_signer.address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(self.random_signer.address, 1)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])
        for signatory_address in self.signatories:
            storage_key = state_container.paginated_tx_hash.generate_key(signatory_address, 1)
            self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.random_signer.address,
                                                                                           tx.ots_key))
        AddressState.put_addresses_state(self.state, addresses_state)
        state_container.paginated_multisig_address.put_paginated_data(None)
        multi_sig_addresses_state = MultiSigAddressState.get_multi_sig_address_state_by_address(
            self.state._db,
            MultiSigAddressState.generate_multi_sig_address(tx.txhash))

        self.assertEqual(self.signatories, multi_sig_addresses_state.signatories)
        self.assertEqual(self.weights, multi_sig_addresses_state.weights)
        self.assertEqual(self.threshold, multi_sig_addresses_state.threshold)

        for signatory_address in self.signatories:
            multi_sig_addresses = state_container.paginated_multisig_address.get_paginated_data(signatory_address, 1)
            self.assertEqual(len(multi_sig_addresses), 1)

        tx.revert(self.state, state_container)
        state_container.paginated_multisig_address.put_paginated_data(None)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.random_signer.address,
                                                                                            tx.ots_key))
        self.assertIsNone(MultiSigAddressState.get_multi_sig_address_state_by_address(
            self.state._db,
            MultiSigAddressState.generate_multi_sig_address(tx.txhash)))

        for signatory_address in self.signatories:
            multi_sig_addresses = state_container.paginated_multisig_address.get_paginated_data(signatory_address, 1)
            self.assertEqual(len(multi_sig_addresses), 0)

    def test_apply_multi_sig_create_txn2(self):
        """
        Features Tested
        - Multi Sig Create txn with duplicate signatories

        Expectation
        - It should result into custom validation error throwing ValueError exception
        :return:
        """
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.random.address: OptimizedAddressState.get_default(self.random.address),
            self.random_signer.address: OptimizedAddressState.get_default(self.random_signer.address),
        }
        addresses_state[self.random_signer.address].pbdata.balance = 200
        modified_signatories = list(self.signatories)
        modified_weights = list(self.weights)

        # Appending bob as signatory second time
        modified_signatories.append(self.bob.address)
        modified_weights.append(2)

        tx = None
        with self.assertRaises(ValueError):
            tx = MultiSigCreate.create(modified_signatories,
                                       modified_weights,
                                       self.threshold,
                                       1,
                                       self.random_signer.pk)
        self.assertIsNone(tx)

    def test_affected_address(self):
        # This transaction can only involve 2 addresses.
        affected_addresses = set()
        tx = MultiSigCreate.create(self.signatories,
                                   self.weights,
                                   self.threshold,
                                   1,
                                   self.random_signer.pk)
        tx.set_affected_address(affected_addresses)

        self.assertEqual(4, len(affected_addresses))
        self.assertIn(self.random_signer.address, affected_addresses)
        for signatory_address in self.signatories:
            self.assertIn(signatory_address, affected_addresses)
