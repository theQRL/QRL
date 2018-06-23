# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from os import urandom

from mock import Mock, patch, PropertyMock
from pyqrllib.pyqrllib import hstr2bin
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.generated import qrlstateinfo_pb2
from qrl.core import config
from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_default_balance_size, set_qrl_dir, replacement_getTime

logger.initialize_default()

alice = get_alice_xmss()
bob = get_bob_xmss()


def ask_difficulty_tracker(difficulty: str):
    dt = DifficultyTracker()
    tmp_difficulty = StringToUInt256('2')
    tmp_target = dt.get_target(tmp_difficulty)
    return tmp_difficulty, tmp_target


def create_block(block_number, previous_block, miner_address):
    return Block.create(block_number=block_number,
                        prev_headerhash=previous_block.headerhash,
                        prev_timestamp=previous_block.timestamp,
                        transactions=[],
                        miner_address=miner_address
                        )


def create_m_block(block_number, previous_block, miner_address):
    mock_block = Mock(
        autospec=Block,
        name="Mock Block {}".format(block_number),
        block_number=block_number,
        prev_headerhash=previous_block.headerhash,
        prev_block_timestamp=previous_block.timestamp,
        transactions=[],
        miner_address=miner_address,
        headerhash="Mock Block {} {}".format(block_number, urandom(6)).encode(),
        timestamp=replacement_getTime()
    )
    mock_block.serialize.return_value = "Mock Block {}".format(block_number).encode()
    return mock_block


class TestChainManagerReal(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()
            self.state.get_measurement = Mock(return_value=10000000)

            del GenesisBlock.instance  # Removing Singleton instance
            self.genesis_block = GenesisBlock()

            self.chain_manager = ChainManager(self.state)
            self.chain_manager._difficulty_tracker = Mock()

    def test_load(self):
        # load() has the following tasks:
        # Write Genesis Block into State immediately
        # Register block_number <-> blockhash mapping
        # Calculate difficulty Metadata for Genesis Block
        # Generate AddressStates from Genesis Block balances
        # Apply Genesis Block's transactions to the state
        self.chain_manager.load(self.genesis_block)
        block = self.state.get_block(GenesisBlock().headerhash)
        self.assertIsNotNone(block)

    def test_load_twice(self):
        self.chain_manager.load(self.genesis_block)

        # If we call load() a second time, it should check to see if we are forked and initiate recovery.
        # First we pretend we are not forked.
        self.state.get_fork_state = Mock(return_value=None)
        self.chain_manager._fork_recovery = Mock(name='mock _fork_recovery()')
        self.chain_manager.load(self.genesis_block)
        self.chain_manager._fork_recovery.assert_not_called()

        # If we pretend we are forked, it should call _fork_recovery().
        m_fork_state = Mock(autospec=qrlstateinfo_pb2.ForkState, initiator_headerhash=self.genesis_block.headerhash)
        self.state.get_fork_state.return_value = m_fork_state
        self.chain_manager.load(self.genesis_block)
        self.chain_manager._fork_recovery.assert_called_with(self.genesis_block, m_fork_state)

    @patch('qrl.core.misc.ntp.getTime')
    def test_simple_add_block(self, time_mock):
        # Simply test that adding a block on top of the genesis block works.
        self.chain_manager._difficulty_tracker.get.return_value = ask_difficulty_tracker('2')
        self.chain_manager.load(self.genesis_block)

        time_mock.return_value = 1615270948  # Very high to get an easy difficulty

        block_1 = Block.create(block_number=1,
                               prev_headerhash=self.genesis_block.headerhash,
                               prev_timestamp=self.genesis_block.timestamp,
                               transactions=[],
                               miner_address=alice.address)
        block_1.set_nonces(201, 0)

        # Uncomment only to determine the correct mining_nonce of above blocks
        # from qrl.core.PoWValidator import PoWValidator
        # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
        #     block_1.set_nonces(block_1.mining_nonce + 1)
        #     print(block_1.mining_nonce)
        self.assertTrue(block_1.validate(self.chain_manager, {}))
        result = self.chain_manager.add_block(block_1)

        self.assertTrue(result)
        self.assertEqual(self.chain_manager.last_block, block_1)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_multi_output_transaction_add_block(self, time_mock):
        # Test that adding block with a multi-output Transaction updates everybody's balances correctly.
        self.chain_manager.load(self.genesis_block)

        extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                        "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
        random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))

        transfer_transaction = TransferTransaction.create(addrs_to=[alice.address, random_xmss.address],
                                                          amounts=[40 * int(config.dev.shor_per_quanta),
                                                                   59 * int(config.dev.shor_per_quanta)],
                                                          fee=1 * config.dev.shor_per_quanta,
                                                          xmss_pk=bob.pk)
        transfer_transaction._data.nonce = 1
        transfer_transaction.sign(bob)

        time_mock.return_value = 1615270948  # Very high to get an easy difficulty

        block_1 = Block.create(block_number=1,
                               prev_headerhash=self.genesis_block.headerhash,
                               prev_timestamp=self.genesis_block.timestamp,
                               transactions=[transfer_transaction],
                               miner_address=alice.address)
        block_1.set_nonces(129, 0)

        # Uncomment only to determine the correct mining_nonce of above blocks
        # from qrl.core.PoWValidator import PoWValidator
        # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
        #     block_1.set_nonces(block_1.mining_nonce + 1)
        #     print(block_1.mining_nonce)
        self.assertTrue(block_1.validate(self.chain_manager, {}))
        result = self.chain_manager.add_block(block_1)

        self.assertTrue(result)
        self.assertEqual(self.chain_manager.last_block, block_1)

        bob_addr_state = self.state.get_address_state(bob.address)
        alice_addr_state = self.state.get_address_state(alice.address)
        random_addr_state = self.state.get_address_state(random_xmss.address)

        self.assertEqual(bob_addr_state.balance, 0)
        self.assertEqual(alice_addr_state.balance,
                         140 * int(config.dev.shor_per_quanta) + block_1.block_reward + block_1.fee_reward)
        self.assertEqual(random_addr_state.balance, 159 * int(config.dev.shor_per_quanta))

    @patch("qrl.core.DifficultyTracker.DifficultyTracker.get")
    def test_add_block(self, mock_difficulty_tracker_get):
        """
        Add block_1 on genesis block (that registers Bob as Alice's slave)
        Add a competing fork_block on genesis block (without the SlaveTransaction)
        Add block_2 on fork_block (without the SlaveTransaction)
        Bob should be free from slavery now.
        """
        mock_difficulty_tracker_get.return_value = ask_difficulty_tracker('2')
        self.chain_manager.load(self.genesis_block)

        # Add block_1 on genesis block.
        slave_tx = SlaveTransaction.create(slave_pks=[bob.pk],
                                           access_types=[0],
                                           fee=0,
                                           xmss_pk=alice.pk)
        slave_tx.sign(alice)
        slave_tx._data.nonce = 1
        self.assertTrue(slave_tx.validate())
        with patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[slave_tx],
                                   miner_address=alice.address)
            block_1.set_nonces(2, 0)
            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
            #     block_1.set_nonces(block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

        self.assertTrue(result)
        self.assertEqual(self.chain_manager.last_block, block_1)

        # Yes, Bob is Alice's slave.
        alice_state = self.chain_manager.get_address_state(alice.address)
        self.assertEqual(len(alice_state.slave_pks_access_type), 1)
        self.assertTrue(str(bob.pk) in alice_state.slave_pks_access_type)

        # Add fork block on genesis block
        with patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1715270948  # Very high to get an easy difficulty
            fork_block = Block.create(block_number=1,
                                      prev_headerhash=self.genesis_block.headerhash,
                                      prev_timestamp=self.genesis_block.timestamp,
                                      transactions=[],
                                      miner_address=bob.address)

            fork_block.set_nonces(4, 0)
            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, fork_block.blockheader, False):
            #     fork_block.set_nonces(fork_block.mining_nonce + 1)
            #     print(fork_block.mining_nonce)
            self.assertTrue(fork_block.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(fork_block)

        self.assertTrue(result)
        self.assertEqual(self.chain_manager.last_block, block_1)

        fork_block = self.state.get_block(fork_block.headerhash)
        self.assertIsNotNone(fork_block)

        # Add block_2 on fork_block.
        with patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1815270948  # Very high to get an easy difficulty
            block_2 = fork_block.create(block_number=2,
                                        prev_headerhash=fork_block.headerhash,
                                        prev_timestamp=fork_block.timestamp,
                                        transactions=[],
                                        miner_address=bob.address)

            block_2.set_nonces(1, 0)
            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(state, block_2.blockheader, False):
            #     block_2.set_nonces(block_2.mining_nonce + 1, 0)
            #     print(block_2.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)

        self.assertTrue(result)
        self.assertEqual(self.chain_manager.last_block.block_number, block_2.block_number)
        self.assertEqual(self.chain_manager.last_block.serialize(), block_2.serialize())

        # Now we are on the forked chain, Bob is no longer Alice's slave.
        alice_state = self.chain_manager.get_address_state(alice.address)
        self.assertFalse(str(bob.pk) in alice_state.slave_pks_access_type)

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def test_get_headerhashes(self):
        block_1 = create_block(1, self.genesis_block, alice.address)
        block_2 = create_block(2, block_1, alice.address)

        self.chain_manager.load(self.genesis_block)
        self.chain_manager.add_block(block_1)
        self.chain_manager.add_block(block_2)

        node_header_hash = self.chain_manager.get_headerhashes(0)
        self.assertEqual(node_header_hash.headerhashes,
                         [self.genesis_block.headerhash, block_1.headerhash, block_2.headerhash])

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def test_fork_recovery(self):
        # When the node finds that it has been on the slower chain all this time, it runs _fork_recovery() to _rollback
        # to an earlier state and switch to the longer chain.

        block_1 = create_block(1, self.genesis_block, alice.address)

        block_2 = create_block(2, block_1, alice.address)
        block_3 = create_block(3, block_2, alice.address)
        self.main_chain = [block_2, block_3]

        block_2_alt = create_block(2, block_1, bob.address)
        block_3_alt = create_block(3, block_2_alt, bob.address)
        block_4_alt = create_block(4, block_3_alt, bob.address)
        self.alt_chain = [block_2_alt, block_3_alt, block_4_alt]

        self.chain_manager.load(self.genesis_block)

        self.chain_manager.add_block(block_1)
        self.chain_manager.add_block(block_2)
        self.chain_manager.add_block(block_3)

        # Start adding the forked block to the chain manager. It accepts, and does nothing else.
        self.chain_manager.add_block(block_2_alt)
        self.assertEqual(self.chain_manager.last_block, block_3)

        # We lengthen the fork. Still, the chain manager stays on the first chain.
        self.chain_manager.add_block(block_3_alt)
        self.assertEqual(self.chain_manager.last_block, block_3)

        # When it is obvious that the fork is longer (has a higher cum. diff), the chain manager invokes _fork_recovery()
        # and switches over to the fork
        self.chain_manager.add_block(block_4_alt)
        self.assertEqual(self.chain_manager.last_block, block_4_alt)


class TestChainManager(TestCase):
    def setUp(self):
        self.state = Mock(autospec=State)
        self.state.get_measurement.return_value = 10000000

        del GenesisBlock.instance  # Removing Singleton instance
        self.genesis_block = GenesisBlock()

        self.chain_manager = ChainManager(self.state)
        self.chain_manager.tx_pool = Mock()
        self.chain_manager._difficulty_tracker = Mock()

    def test_fork_recovery_failed(self):
        # When switching to the longer chain fails, _fork_recovery() must _rollback and restore the shorter chain.
        # Mock out irrelevant functions
        self.chain_manager._update_block_number_mapping = Mock()

        # Switching to the new chain should fail!
        self.chain_manager.add_chain = Mock(return_value=False)
        self.chain_manager._rollback = Mock()

        block_1 = create_m_block(1, self.genesis_block, alice.address)
        block_2 = create_m_block(2, block_1, alice.address)

        block_1_alt = create_m_block(1, self.genesis_block, alice.address)
        block_2_alt = create_m_block(2, block_1_alt, alice.address)
        block_3_alt = create_m_block(3, block_2_alt, alice.address)

        fork_state = qrlstateinfo_pb2.ForkState(
            initiator_headerhash=block_3_alt.headerhash,
            fork_point_headerhash=self.genesis_block.headerhash,
            old_mainchain_hash_path=[b.headerhash for b in [block_1, block_2]],
            new_mainchain_hash_path=[b.headerhash for b in [block_1_alt, block_2_alt, block_3_alt]]
        )

        # _fork_recovery() will _rollback() to the genesis block and go on the longer chain.
        # At this point, _rollback() should return the old hash path as a backup
        # in case switching to the longer chain fails.
        self.chain_manager._rollback.return_value = [block_2.headerhash, block_1.headerhash]

        self.chain_manager._fork_recovery(block_3_alt, fork_state)

        # _fork_recovery() should have _rollback()ed when trying to switch to the longer chain
        self.chain_manager._rollback.assert_any_call(self.genesis_block.headerhash, fork_state)
        # _fork_recovery() should have _rollback()ed to the genesis block when trying to restore the shorter chain
        self.chain_manager._rollback.assert_called_with(self.genesis_block.headerhash)

    def test_fork_recovery_rollbacked_already(self):
        # Switching to the new chain works, but test that if the _rollback() has already happened, _fork_recovery() does
        # not hiccup

        # Mock out irrelevant functions
        self.chain_manager._update_block_number_mapping = Mock()

        # Switching to the new chain should succeed!
        self.chain_manager.add_chain = Mock(return_value=True)
        self.chain_manager._rollback = Mock()

        block_1 = create_m_block(1, self.genesis_block, alice.address)
        block_2 = create_m_block(2, block_1, alice.address)

        block_1_alt = create_m_block(1, self.genesis_block, alice.address)
        block_2_alt = create_m_block(2, block_1_alt, alice.address)
        block_3_alt = create_m_block(3, block_2_alt, alice.address)

        fork_state = qrlstateinfo_pb2.ForkState(
            initiator_headerhash=block_3_alt.headerhash,
            fork_point_headerhash=self.genesis_block.headerhash,
            old_mainchain_hash_path=[b.headerhash for b in [block_1, block_2]],
            new_mainchain_hash_path=[b.headerhash for b in [block_1_alt, block_2_alt, block_3_alt]]
        )

        # State.get_block() should say that we are already on block_1_alt
        self.chain_manager._state.get_block.return_value = block_1_alt

        # _fork_recovery() will not call _rollback(), because it has already happened.
        self.chain_manager._fork_recovery(block_3_alt, fork_state)

        # _fork_recovery() should have _rollback()ed when trying to switch to the longer chain
        self.chain_manager._rollback.assert_not_called()

    @patch('qrl.core.config')
    @patch('qrl.core.ChainManager.ChainManager.height', new_callable=PropertyMock)
    def test_add_block_doesnt_add_blocks_beyond_reorg_limit(self, m_height, m_config):
        # If we are at height 40000, what's the use of adding a block that's height 1? Simply ignore that block.
        m_config.dev.reorg_limit = 22000
        m_height.return_value = 40000
        block_1 = create_m_block(1, self.genesis_block, alice.address)

        ans = self.chain_manager.add_block(block_1)
        self.assertFalse(ans)

    def test_add_block_refuses_to_add_too_large_blocks(self):
        # State.get_block_size_limit() calculates how large each Block should be from the last 10 confirmed blocks.
        self.state.get_block_size_limit.return_value = 5000000
        block_1 = create_m_block(1, self.genesis_block, alice.address)
        block_1.size = 6000000

        ans = self.chain_manager.add_block(block_1)
        self.assertFalse(ans)

    def test_get_fork_point_failure_modes(self):
        block_0 = create_m_block(0, Mock(headerhash=b'Fake Genesis', timestamp=replacement_getTime()), alice.address)
        block_1 = create_m_block(1, block_0, alice.address)
        block_2 = create_m_block(2, block_1, alice.address)

        # If _get_fork_point() ever reaches block_number 0, that means the genesis block is different!
        # Mock self.state leads us back to block_0
        self.state.get_block.side_effect = [block_2, block_1, block_0]

        with self.assertRaises(Exception):
            self.chain_manager._get_fork_point(block_2)

        # If _get_fork_point() cannot find a particular block while walking back to the fork point, something has gone
        # very wrong
        # Mock self.state leads us back through a broken chain
        self.state.get_block.side_effect = [block_2, None, block_0]

        with self.assertRaises(Exception):
            self.chain_manager._get_fork_point(block_2)

    def test_apply_block_fails_if_state_changes_fail(self):
        # ChainManager._apply_block() should fail if Block.apply_state_changes() fails.
        block = create_m_block(50, self.genesis_block, alice.address)
        block.apply_state_changes.return_value = False

        ans = self.chain_manager._apply_block(block, [])
        self.assertFalse(ans)

    def test_try_branch_add_block_fails_if_apply_block_fails(self):
        # ChainManager._try_branch_add_block() should fail if ChainManager._apply_block() fails
        self.chain_manager._apply_block = Mock(return_value=False)

        block = create_m_block(50, self.genesis_block, alice.address)

        block_added, fork_flag = self.chain_manager._try_branch_add_block(block, [])
        self.assertFalse(block_added)
        self.assertFalse(fork_flag)

    def test_add_chain_fails_if_fork_recovery_didnt_complete_successfully(self):
        block_1 = create_m_block(1, self.genesis_block, alice.address)
        block_2 = create_m_block(2, block_1, alice.address)

        block_1_alt = create_m_block(1, self.genesis_block, alice.address)
        block_2_alt = create_m_block(2, block_1_alt, alice.address)
        block_3_alt = create_m_block(3, block_2_alt, alice.address)

        fork_state = qrlstateinfo_pb2.ForkState(
            initiator_headerhash=block_3_alt.headerhash,
            fork_point_headerhash=self.genesis_block.headerhash,
            old_mainchain_hash_path=[b.headerhash for b in [block_1, block_2]],
            new_mainchain_hash_path=[b.headerhash for b in [block_1_alt, block_2_alt, block_3_alt]]
        )
        # We want to add_chain(block_*_alt chain), but we're still on block_1 (we should have rolled back to genesis)
        self.chain_manager._last_block = block_1
        ans = self.chain_manager.add_chain([block_1_alt.headerhash, block_2_alt.headerhash], fork_state)
        self.assertFalse(ans)

    def test_add_chain_fails_if_apply_block_fails(self):
        block_1 = create_m_block(1, self.genesis_block, alice.address)
        block_2 = create_m_block(2, block_1, alice.address)

        block_1_alt = create_m_block(1, self.genesis_block, alice.address)
        block_2_alt = create_m_block(2, block_1_alt, alice.address)
        block_3_alt = create_m_block(3, block_2_alt, alice.address)

        fork_state = qrlstateinfo_pb2.ForkState(
            initiator_headerhash=block_3_alt.headerhash,
            fork_point_headerhash=self.genesis_block.headerhash,
            old_mainchain_hash_path=[b.headerhash for b in [block_1, block_2]],
            new_mainchain_hash_path=[b.headerhash for b in [block_1_alt, block_2_alt, block_3_alt]]
        )

        # we want to add_chain(block_*_alt chain), but for some reason applying a Block to the State didn't work.
        self.chain_manager._apply_block = Mock(return_value=False)
        ans = self.chain_manager.add_chain([block_1_alt.headerhash, block_2_alt.headerhash], fork_state)
        self.assertFalse(ans)

    def test_get_transaction(self):
        # get_transaction() is simply a wrapper for State.get_tx_metadata
        self.chain_manager.get_tx_metadata(b'txhash')
        self.state.get_tx_metadata.assert_called_once()
