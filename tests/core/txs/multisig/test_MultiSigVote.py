from unittest import TestCase

import simplejson as json

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.VoteStats import VoteStats
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from tests.core.txs.testdata import test_json_MultiSigVote
from qrl.generated.qrl_pb2 import SlaveMetadata
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir, set_hard_fork_block_number

logger.initialize_default()


class TestMultiSigVote(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMultiSigVote, self).__init__(*args, **kwargs)
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
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
                                 fee=0,
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        self.assertIsInstance(tx, MultiSigVote)

    def test_to_json(self):
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
                                 fee=0,
                                 xmss_pk=self.alice.pk)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_MultiSigVote), json.loads(txjson))

    def test_validate_custom(self):
        """
        MultiSigCreate _validate_custom() only checks if fee == 0
        """
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
                                 fee=0,
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        result = tx._validate_custom()
        self.assertTrue(result)

    @set_hard_fork_block_number()
    def test_validate_extended(self):
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
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
        vote_stats = {
            spend_tx.txhash: VoteStats.create(multi_sig_address=multi_sig_address,
                                              shared_key=spend_tx.txhash,
                                              signatories=multi_sig_address_state.signatories,
                                              expiry_block_number=spend_tx.expiry_block_number),
        }
        multi_sig_spend_txs = {
            spend_tx.txhash: spend_tx,
        }
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=None,
                                         batch=None)

        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        tx._data.multi_sig_vote.unvote = True
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        tx._data.multi_sig_vote.unvote = False
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        alice_address_state.pbdata.balance = 0
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        alice_address_state.pbdata.balance = 5
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        state_container.block_number = 15000
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        state_container.block_number = 15001
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

    @set_hard_fork_block_number()
    def test_validate_all(self):
        """
        Test for Validate Extended when transaction has been signed by slave.
        :return:
        """
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
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
        vote_stats = {
            spend_tx.txhash: VoteStats.create(multi_sig_address=multi_sig_address,
                                              shared_key=spend_tx.txhash,
                                              signatories=multi_sig_address_state.signatories,
                                              expiry_block_number=spend_tx.expiry_block_number),
        }
        multi_sig_spend_txs = {
            spend_tx.txhash: spend_tx,
        }
        slaves = Indexer(b'slave', None)
        slaves.data[(self.alice.address, self.random.pk)] = SlaveMetadata(access_type=0)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=slaves,
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
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
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
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
        vote_stats = {
            spend_tx.txhash: VoteStats.create(multi_sig_address=multi_sig_address,
                                              shared_key=spend_tx.txhash,
                                              signatories=multi_sig_address_state.signatories,
                                              expiry_block_number=spend_tx.expiry_block_number),
        }
        multi_sig_spend_txs = {
            spend_tx.txhash: spend_tx,
        }
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
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
        self.assertIn(spend_tx.txhash, state_container.votes_stats)
        vote_stats = state_container.votes_stats[spend_tx.txhash]
        unvote, index = vote_stats.get_unvote_by_address(tx.addr_from)
        self.assertNotEqual(index, -1)
        self.assertFalse(unvote)
        self.assertEqual(vote_stats.shared_key, spend_tx.txhash)
        self.assertEqual(vote_stats.total_weight, 4)
        self.assertEqual(vote_stats.signatories, multi_sig_address_state.signatories)

    def test_revert(self):
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
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
        vote_stats = {
            spend_tx.txhash: VoteStats.create(multi_sig_address=multi_sig_address,
                                              shared_key=spend_tx.txhash,
                                              signatories=multi_sig_address_state.signatories,
                                              expiry_block_number=spend_tx.expiry_block_number),
        }
        multi_sig_spend_txs = {
            spend_tx.txhash: spend_tx,
        }
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
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
        self.assertIn(spend_tx.txhash, state_container.votes_stats)
        vote_stats = state_container.votes_stats[spend_tx.txhash]
        unvote, index = vote_stats.get_unvote_by_address(tx.addr_from)
        self.assertNotEqual(index, -1)
        self.assertFalse(unvote)
        self.assertEqual(vote_stats.shared_key, spend_tx.txhash)
        self.assertEqual(vote_stats.total_weight, 4)
        self.assertEqual(vote_stats.signatories, multi_sig_address_state.signatories)

        tx.revert(self.state, state_container)
        self.assertIn(spend_tx.txhash, state_container.votes_stats)
        vote_stats = state_container.votes_stats[spend_tx.txhash]
        unvote, index = vote_stats.get_unvote_by_address(tx.addr_from)
        self.assertNotEqual(index, -1)
        self.assertTrue(unvote)
        self.assertEqual(vote_stats.shared_key, spend_tx.txhash)
        self.assertEqual(vote_stats.total_weight, 0)
        self.assertEqual(vote_stats.signatories, multi_sig_address_state.signatories)

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                            tx.ots_key))

    def test_affected_address(self):
        # This transaction can only involve 2 addresses.
        affected_addresses = set()
        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(b'')
        spend_tx = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                        addrs_to=[self.alice.address],
                                        amounts=[100],
                                        expiry_block_number=15000,
                                        fee=0,
                                        xmss_pk=self.alice.pk)
        spend_tx.sign(self.alice)
        tx = MultiSigVote.create(shared_key=spend_tx.txhash,
                                 unvote=False,
                                 fee=5,
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        tx.set_affected_address(affected_addresses)

        self.assertEqual(1, len(affected_addresses))
        self.assertIn(self.alice.address, affected_addresses)
