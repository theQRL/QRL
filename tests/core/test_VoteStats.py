from unittest import TestCase

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
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir

logger.initialize_default()


class TestVoteStats(TestCase):
    def setUp(self) -> None:
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()
        self.random = get_alice_xmss(4)
        self.random_signer = get_bob_xmss(4)
        self.signatories = [self.alice.address, self.bob.address, self.random.address]
        self.weights = [20, 30, 10]
        self.threshold = 30

    def test_apply_and_put(self):
        """
        Test execution of multisig spend txn, when threshold is not met.
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        # Expected balance is 0, as 5 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_revert_and_put(self):
        """
        Test execution of multisig spend txn, when threshold is not met and then reverting the txn.
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        # Expected balance is 0, as 5 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx.revert(self.state, state_container))

        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 5)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_apply_and_put2(self):
        """
        Test execution of multi sig txn, when threshold is met.
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
        tx1 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx1.sign(self.alice)

        tx2 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=4,
                                  xmss_pk=self.bob.pk)
        tx2.sign(self.bob)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        bob_address_state = OptimizedAddressState.get_default(address=self.bob.address)
        bob_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: bob_address_state,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx1.apply(self.state, state_container))
        self.assertTrue(tx2.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 0)
        # Expected balance is 100, as 5 quanta paid in MultiSigVote txn as a fee
        # and 100 quanta received by multi sig spend txn
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 100)
        # Expected balance is 1, as 4 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.bob.address].balance, 1)
        self.assertTrue(vote_stats[spend_tx.txhash].executed)

    def test_revert_and_put2(self):
        """
        Test execution of multi sig txn, when threshold is met and then reverting the txn.
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
        tx1 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx1.sign(self.alice)

        tx2 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=4,
                                  xmss_pk=self.bob.pk)
        tx2.sign(self.bob)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        bob_address_state = OptimizedAddressState.get_default(address=self.bob.address)
        bob_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: bob_address_state,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx1.apply(self.state, state_container))
        self.assertTrue(tx2.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 0)
        # Expected balance is 100, as 5 quanta paid in MultiSigVote txn as a fee
        # and 100 quanta received by multi sig spend txn
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 100)
        # Expected balance is 1, as 4 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.bob.address].balance, 1)
        self.assertTrue(vote_stats[spend_tx.txhash].executed)

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx1.revert(self.state, state_container))
        self.assertTrue(tx2.revert(self.state, state_container))

        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 5)
        self.assertEqual(state_container.addresses_state[self.bob.address].balance, 5)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_apply_and_put3(self):
        """
        Test execution of multisig spend txn, when threshold is met by a single txn.
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
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=4,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 0)
        # Expected balance is 100, as 5 quanta paid in MultiSigVote txn as a fee
        # and 100 quanta received by multi sig spend txn
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 100)
        self.assertTrue(vote_stats[spend_tx.txhash].executed)

    def test_revert_and_put3(self):
        """
        Test execution of multisig spend txn, when threshold is met by a single txn and then reverting the txn.
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
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=4,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 0)
        # Expected balance is 100, as 5 quanta paid in MultiSigVote txn as a fee
        # and 100 quanta received by multi sig spend txn
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 100)
        self.assertTrue(vote_stats[spend_tx.txhash].executed)

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx.revert(self.state, state_container))
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 5)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_apply_and_put4(self):
        """
        Test execution of multisig spend txn, when threshold is met but multi_sig address doesn't have
        sufficient balance.
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
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=90,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=4,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        # Expected balance is 90, as multi_sig_spend txn is not executed due to insufficient balance
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        # Expected balance is 0, as 5 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_revert_and_put4(self):
        """
        Test execution of multisig spend txn, when threshold is met but multi_sig address doesn't have
        sufficient balance and then reverting the txn.
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
                                 xmss_pk=self.alice.pk)
        tx.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=90,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=4,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        # Expected balance is 90, as multi_sig_spend txn is not executed due to insufficient balance
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        # Expected balance is 0, as 5 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx.revert(self.state, state_container))

        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 5)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_apply_and_put5(self):
        """
        Test execution of multisig spend txn, when threshold is met but multi_sig address doesn't have
        sufficient balance, later somehow multi sig address gets sufficient balance, before expiry.
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
        tx1 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx1.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=90,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=4,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx1.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        # Expected balance is 90, as multi_sig_spend txn is not executed due to insufficient balance
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        # Expected balance is 0, as 5 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        multi_sig_address_state.pbdata.balance = 100
        tx2 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=True,
                                  fee=0,
                                  xmss_pk=self.alice.pk)
        tx2.sign(self.alice)

        self.assertTrue(tx2.apply(self.state, state_container))
        VoteStats.put_all(self.state, state_container)
        # Expected balance is 100
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        tx3 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=0,
                                  xmss_pk=self.alice.pk)
        tx3.sign(self.alice)
        self.assertTrue(tx3.apply(self.state, state_container))
        VoteStats.put_all(self.state, state_container)
        # Expected balance is 0, as multi_sig_spend txn has been executed
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 0)
        # Expected balance is 100, as 5 quanta paid in MultiSigVote txn as a fee
        # and 100 quanta received by multi sig spend txn
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 100)
        self.assertTrue(vote_stats[spend_tx.txhash].executed)

    def test_revert_and_put5(self):
        """
        Test execution of multisig spend txn, when threshold is met but multi_sig address doesn't have
        sufficient balance, later somehow multi sig address gets sufficient balance, before expiry.
        Then fork recovery is called.
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
        tx1 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx1.sign(self.alice)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=90,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=4,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=10,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertTrue(tx1.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        # Expected balance is 90, as multi_sig_spend txn is not executed due to insufficient balance
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        # Expected balance is 0, as 5 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        multi_sig_address_state.pbdata.balance = 100
        tx2 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=True,
                                  fee=0,
                                  xmss_pk=self.alice.pk)
        tx2.sign(self.alice)

        self.assertTrue(tx2.apply(self.state, state_container))
        VoteStats.put_all(self.state, state_container)
        # Expected balance is 100
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        tx3 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=0,
                                  xmss_pk=self.alice.pk)
        tx3.sign(self.alice)
        self.assertTrue(tx3.apply(self.state, state_container))
        VoteStats.put_all(self.state, state_container)
        # Expected balance is 0, as multi_sig_spend txn has been executed
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 0)
        # Expected balance is 100, as 5 quanta paid in MultiSigVote txn as a fee
        # and 100 quanta received by multi sig spend txn
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 100)
        self.assertTrue(vote_stats[spend_tx.txhash].executed)

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx3.revert(self.state, state_container))
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        multi_sig_address_state.pbdata.balance = 90

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx2.revert(self.state, state_container))
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)

        VoteStats.revert_all(self.state, state_container)
        self.assertTrue(tx1.revert(self.state, state_container))
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 90)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 5)

    def test_apply_and_put6(self):
        """
        Test execution of multi sig txn, when threshold is met but after the block expiry.
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
        tx1 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx1.sign(self.alice)

        tx2 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=4,
                                  xmss_pk=self.bob.pk)
        tx2.sign(self.bob)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        bob_address_state = OptimizedAddressState.get_default(address=self.bob.address)
        bob_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: bob_address_state,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=15001,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertFalse(tx1.apply(self.state, state_container))
        self.assertFalse(tx2.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

    def test_revert_and_put6(self):
        """
        Test execution of multi sig txn, when threshold is met but after the block expiry.
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
        tx1 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=5,
                                  xmss_pk=self.alice.pk)
        tx1.sign(self.alice)

        tx2 = MultiSigVote.create(shared_key=spend_tx.txhash,
                                  unvote=False,
                                  fee=4,
                                  xmss_pk=self.bob.pk)
        tx2.sign(self.bob)

        alice_address_state = OptimizedAddressState.get_default(address=self.alice.address)
        alice_address_state.pbdata.balance = 5
        bob_address_state = OptimizedAddressState.get_default(address=self.bob.address)
        bob_address_state.pbdata.balance = 5
        multi_sig_address_state = MultiSigAddressState.create(creation_tx_hash=b'',
                                                              balance=100,
                                                              signatories=[self.alice.address, self.bob.address],
                                                              weights=[4, 6],
                                                              threshold=5,
                                                              transaction_hash_count=0)
        addresses_state = {
            self.alice.address: alice_address_state,
            self.bob.address: bob_address_state,
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
                                         tokens=Indexer(b'token', self.state._db),
                                         slaves=Indexer(b'slave', self.state._db),
                                         lattice_pk=Indexer(b'lattice_pk', self.state._db),
                                         multi_sig_spend_txs=multi_sig_spend_txs,
                                         votes_stats=vote_stats,
                                         block_number=15001,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertFalse(tx1.apply(self.state, state_container))
        self.assertFalse(tx2.apply(self.state, state_container))

        VoteStats.put_all(self.state, state_container)
        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
        self.assertEqual(state_container.addresses_state[self.alice.address].balance, 0)
        # Expected balance is 1, as 4 quanta paid in MultiSigVote txn as a fee
        self.assertEqual(state_container.addresses_state[self.bob.address].balance, 1)
        self.assertFalse(vote_stats[spend_tx.txhash].executed)

        VoteStats.revert_all(self.state, state_container)
        self.assertFalse(tx2.revert(self.state, state_container))
        self.assertFalse(tx1.revert(self.state, state_container))

        self.assertEqual(state_container.addresses_state[multi_sig_address].balance, 100)
