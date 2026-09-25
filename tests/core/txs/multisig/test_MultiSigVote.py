from unittest import TestCase

import simplejson as json

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.core.misc import logger
from qrl.core.VoteStats import VoteStats
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from tests.core.txs.testdata import test_json_MultiSigVote
from qrl.generated.qrl_pb2 import SlaveMetadata
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir, set_hard_fork_block_number
from tests.misc.multisig_expiry import MultiSigExpiryTestCase

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

    def test_validate_tx_max_size(self):
        tx = MultiSigVote.create(shared_key=b'0' * 32,
                                 unvote=True,
                                 fee=2 ** 64 - 1,
                                 xmss_pk=self.alice.pk,
                                 master_addr=self.bob.address)
        tx._data.nonce = 2 ** 64 - 1
        tx.sign(self.alice)
        tx._data.signature = b'8' * 3140  # max expected signature size based on height 30
        tx._data.multi_sig_vote.prev_tx_hash = b'0' * 32

        self.assertTrue(tx._validate_custom())
        self.assertEqual(tx.size, tx.max_size_limit)

    def test_validate_tx_exceeds_max_size(self):
        tx = MultiSigVote.create(shared_key=b'0' * 32,
                                 unvote=True,
                                 fee=2 ** 64 - 1,
                                 xmss_pk=self.alice.pk,
                                 master_addr=self.bob.address)
        tx._data.nonce = 2 ** 64 - 1
        tx.sign(self.alice)
        tx._data.signature = b'8' * 3141  # 1 byte over max expected signature size

        self.assertFalse(tx._validate_custom())


class TestMultiSigVoteExpiry(MultiSigExpiryTestCase):
    def confirm_spends(self, expiries):
        """Persist spend proposals before the current tip so votes can reference them."""
        spends = [self.make_spend(expiry) for expiry in expiries]
        for nonce, spend in enumerate(spends, 1):
            spend.pbdata.nonce = nonce
        block = Block.create(dev_config=config.dev,
                             block_number=self.tip - 2,
                             prev_headerhash=b'\x04' * 32,
                             prev_timestamp=1526830525,
                             transactions=spends,
                             miner_address=self.bob.address,
                             seed_height=0,
                             seed_hash=b'\x05' * 32)
        batch = self.state.batch
        self.assertTrue(self.chain_manager._apply_state_changes(block, batch))
        self.assertTrue(TransactionMetadata.update_tx_metadata(self.state, block, batch))
        self.state.write_batch(batch)
        return spends

    def make_vote(self, spend, fee=1):
        tx = MultiSigVote.create(shared_key=spend.txhash,
                                 unvote=False,
                                 fee=fee,
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        tx.pbdata.nonce = self.chain_manager.get_optimized_address_state(self.alice.address).nonce + 1
        return tx

    def test_admission_rejects_votes_expired_before_the_next_block(self):
        spends = self.confirm_spends([self.tip - 1, self.tip])
        for spend in spends:
            with self.subTest(expiry=spend.expiry_block_number):
                tx = self.make_vote(spend)
                self.assertFalse(self.chain_manager.validate_all(tx, check_nonce=False))

    def test_admission_accepts_votes_expiring_at_or_after_the_next_block(self):
        spends = self.confirm_spends([self.tip + 1, self.tip + 2])
        for spend in spends:
            with self.subTest(expiry=spend.expiry_block_number):
                tx = self.make_vote(spend)
                self.assertTrue(self.chain_manager.validate_all(tx, check_nonce=False))

    def test_miner_removes_expired_vote_and_executes_vote_at_expiry(self):
        expired_spend, valid_spend = self.confirm_spends([self.tip, self.tip + 1])
        expired = self.make_vote(expired_spend, fee=5)
        valid = self.make_vote(valid_spend)
        self.assertTrue(self.pool.add_tx_to_pool(expired, self.tip))
        self.assertTrue(self.pool.add_tx_to_pool(valid, self.tip))
        valid_size = valid.size

        block = self.mine_next_block()

        self.assertIsNotNone(block)
        self.assertEqual(block.block_number, valid_spend.expiry_block_number)
        self.assertEqual([tx.transaction_hash for tx in block.transactions[1:]], [valid.txhash])
        self.assertEqual(self.pool.get_tx_index_from_pool(expired.txhash), -1)
        self.assertEqual(self.pool._transaction_pool_size_in_bytes, valid_size)
        batch = self.state.batch
        self.assertTrue(self.chain_manager._apply_state_changes(block, batch))
        self.state.write_batch(batch)
        self.assertTrue(VoteStats.get_state(self.state, valid.shared_key).executed)
        self.assertFalse(VoteStats.get_state(self.state, expired.shared_key).executed)

    def test_miner_removes_vote_that_expires_while_waiting(self):
        spend, = self.confirm_spends([self.tip + 1])
        tx = self.make_vote(spend)
        self.assertTrue(self.chain_manager.validate_all(tx, check_nonce=False))
        self.assertTrue(self.pool.add_tx_to_pool(tx, self.tip))
        self.chain_manager._last_block.block_number += 1

        block = self.mine_next_block()

        self.assertIsNotNone(block)
        self.assertEqual(block.block_number, self.tip + 2)
        self.assertEqual(len(block.transactions), 1)  # Coinbase only.
        self.assertEqual(self.pool.transactions, [])
        self.assertEqual(self.pool._transaction_pool_size_in_bytes, 0)
        self.assertTrue(self.chain_manager._apply_state_changes(block, self.state.batch))

    def test_stale_cleanup_validates_next_block_and_records_current_tip(self):
        expired_spend, valid_spend = self.confirm_spends([self.tip + 3, self.tip + 4])
        expired = self.make_vote(expired_spend, fee=5)
        valid = self.make_vote(valid_spend)
        for tx in (expired, valid):
            self.assertTrue(self.chain_manager.validate_all(tx, check_nonce=False))
            self.assertTrue(self.pool.add_tx_to_pool(tx, self.tip))
        self.chain_manager._last_block.block_number += 3

        self.check_stale()

        self.assertEqual(self.pool.get_tx_index_from_pool(expired.txhash), -1)
        self.assertEqual(len(self.pool.transactions), 1)
        tx_info = self.pool.transactions[0][1]
        self.assertEqual(tx_info.transaction.txhash, valid.txhash)
        self.assertEqual(tx_info.block_number, self.chain_manager.height)
        self.assertEqual(self.pool._transaction_pool_size_in_bytes, valid.size)
        self.broadcast.assert_called_once_with(valid)

    def test_stale_cleanup_preserves_age_threshold(self):
        spend, = self.confirm_spends([self.tip + 2])
        tx = self.make_vote(spend)
        self.assertTrue(self.chain_manager.validate_all(tx, check_nonce=False))
        self.assertTrue(self.pool.add_tx_to_pool(tx, self.tip))
        self.chain_manager._last_block.block_number += 2

        self.check_stale()

        self.assertEqual(len(self.pool.transactions), 1)
        self.assertEqual(self.pool.transactions[0][1].block_number, self.tip)
        self.broadcast.assert_not_called()

        self.chain_manager._last_block.block_number += 1
        self.check_stale()
        self.assertEqual(self.pool.transactions, [])
        self.broadcast.assert_not_called()
