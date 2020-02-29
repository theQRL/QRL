from unittest import TestCase

import simplejson as json

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from tests.core.txs.testdata import test_json_MultiSigSpend
from qrl.generated.qrl_pb2 import SlaveMetadata
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir, set_hard_fork_block_number

logger.initialize_default()


class TestMultiSigSpend(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMultiSigSpend, self).__init__(*args, **kwargs)
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
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=0,
                                  xmss_pk=self.alice.pk)
        self.assertIsInstance(tx, MultiSigSpend)

    def test_to_json(self):
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=0,
                                  xmss_pk=self.alice.pk)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_MultiSigSpend), json.loads(txjson))

    def test_validate_custom(self):
        """
        MultiSigCreate _validate_custom() only checks if fee == 0
        """
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.alice.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=0,
                                  xmss_pk=self.random_signer.pk)
        del tx._data.multi_sig_spend.addrs_to[-1]
        result = tx._validate_custom()
        self.assertFalse(result)

        tx._data.multi_sig_spend.addrs_to.extend([self.alice.address])
        result = tx._validate_custom()
        self.assertTrue(result)

        del tx._data.multi_sig_spend.amounts[-1]
        result = tx._validate_custom()
        self.assertFalse(result)

        tx._data.multi_sig_spend.amounts.extend([100])
        result = tx._validate_custom()
        self.assertTrue(result)

        tx._data.multi_sig_spend.multi_sig_address = self.bob.address
        result = tx._validate_custom()
        self.assertFalse(result)

    @set_hard_fork_block_number()
    def test_validate_extended(self):
        """
        TODO: Check by signing txn from a non signatory address
        """
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        addresses_state = {
            self.alice.address: alice_address_state,
            multi_sig_address: multi_sig_address_state,
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

        alice_address_state.pbdata.balance = 0
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        alice_address_state.pbdata.balance = 5
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        multi_sig_address_state.pbdata.balance = 99
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        multi_sig_address_state.pbdata.balance = 100
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        tx.pbdata.multi_sig_spend.expiry_block_number = 10
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        tx.pbdata.multi_sig_spend.expiry_block_number = 15000
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

    @set_hard_fork_block_number()
    def test_validate_all(self):
        """
        TODO: Check by signing txn from a non signatory address
        """
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=5,
                                  xmss_pk=self.random.pk,
                                  master_addr=self.alice.address)
        tx.sign(self.random)
        tx._data.nonce = 1
        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        random_address_state = OptimizedAddressState.get_default(address=self.random.address)
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.random.address: random_address_state,
            multi_sig_address: multi_sig_address_state,
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

        tx._data.nonce = 2
        result = tx.validate_all(state_container)
        self.assertFalse(result)  # False as nonce is invalid

    def test_apply(self):
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        alice_address_state.pbdata.balance = 5
        bob_address_state = OptimizedAddressState.get_default(self.bob.address)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: bob_address_state,
            multi_sig_address: multi_sig_address_state,
        }

        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx.sign(self.alice)

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

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                            tx.ots_key))

        tx.apply(self.state, state_container)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                           tx.ots_key))
        self.assertIn(tx.txhash, state_container.votes_stats)
        vote_stats = state_container.votes_stats[tx.txhash]
        self.assertEqual(vote_stats.shared_key, tx.txhash)
        self.assertEqual(vote_stats.total_weight, 0)
        self.assertEqual(vote_stats.signatories, multi_sig_address_state.signatories)

    def test_revert(self):
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        alice_address_state.pbdata.balance = 5
        alice_address_state.update_ots_bitfield_used_page()
        alice_address_state.used_ots_key_count += 1
        alice_address_state.update_multi_sig_address_count()
        bob_address_state = OptimizedAddressState.get_default(self.bob.address)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: bob_address_state,
            multi_sig_address: multi_sig_address_state,
        }

        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        tx._data.nonce = 1

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

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                            tx.ots_key))

        tx.apply(self.state, state_container)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                           tx.ots_key))
        self.assertIn(tx.txhash, state_container.votes_stats)
        vote_stats = state_container.votes_stats[tx.txhash]
        self.assertEqual(vote_stats.shared_key, tx.txhash)
        self.assertEqual(vote_stats.total_weight, 0)
        self.assertEqual(vote_stats.signatories, multi_sig_address_state.signatories)

        tx.revert(self.state, state_container)
        self.assertNotIn(tx.txhash, state_container.votes_stats)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                            tx.ots_key))

    def test_affected_address(self):
        # This transaction can only involve 2 addresses.
        affected_addresses = set()
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=15000,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx.set_affected_address(affected_addresses)

        self.assertEqual(3, len(affected_addresses))
        self.assertIn(self.alice.address, affected_addresses)
        self.assertIn(multi_sig_address, affected_addresses)
