# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from os import urandom

from mock import Mock, patch, PropertyMock, MagicMock
from pyqrllib.pyqrllib import hstr2bin
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.generated import qrlstateinfo_pb2
from qrl.core import config
from qrl.crypto.xmss import XMSS
from qrl.crypto.QRandomX import QRandomX
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.ChainManager import ChainManager
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.State import State
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.LatticeTransaction import LatticeTransaction
from qrl.core.txs.multisig.MultiSigCreate import MultiSigCreate
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_default_balance_size, set_hard_fork_block_number, \
    set_qrl_dir, replacement_getTime, get_some_address, gen_blocks

alice = get_alice_xmss()
bob = get_bob_xmss()


def ask_difficulty_tracker(difficulty: str, dev_config: config.DevConfig):
    dt = DifficultyTracker()
    tmp_difficulty = StringToUInt256(difficulty)
    tmp_target = dt.get_target(tmp_difficulty, dev_config)
    return tmp_difficulty, tmp_target


def create_block(block_number, previous_block, miner_address):
    return Block.create(dev_config=config.dev,
                        block_number=block_number,
                        prev_headerhash=previous_block.headerhash,
                        prev_timestamp=previous_block.timestamp,
                        transactions=[],
                        miner_address=miner_address,
                        seed_height=None,
                        seed_hash=None)


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
            self._qn = QRandomX()

            try:
                del GenesisBlock.instance  # Removing Singleton instance
            except Exception:  # noqa
                pass
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
        block = Block.get_block(self.state, GenesisBlock().headerhash)
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
    def test_simple_add_block_multiple_coinbase(self, time_mock):
        # Simply test that adding a block on top of the genesis block works.
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty
            from qrl.core.txs.CoinBase import CoinBase
            exploit_tx = CoinBase.create(config.dev, 250000000, alice.address, 1)
            exploit_tx.pbdata.signature = b'00000000'
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[exploit_tx],
                                   miner_address=alice.address,
                                   seed_hash=None,
                                   seed_height=None)
            block_1.set_nonces(config.dev, 204, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1, 0)
            #     print(block_1.mining_nonce)
            self.assertFalse(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertFalse(result)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_multi_output_transaction_add_block(self, time_mock):
        # Test that adding block with a multi-output Transaction updates everybody's balances correctly.
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))

            transfer_transaction = TransferTransaction.create(addrs_to=[alice.address, random_xmss.address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta),
                                                                       59 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob)

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[transfer_transaction],
                                   miner_address=alice.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_1.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
            #     block_1.set_nonces(block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)

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
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
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

                block_1 = Block.create(dev_config=config.dev,
                                       block_number=1,
                                       prev_headerhash=self.genesis_block.headerhash,
                                       prev_timestamp=self.genesis_block.timestamp,
                                       transactions=[slave_tx],
                                       miner_address=alice.address,
                                       seed_height=None,
                                       seed_hash=None)
                block_1.set_nonces(config.dev, 2, 0)
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
            alice_state = self.chain_manager.get_optimized_address_state(alice.address)
            self.assertEqual(alice_state.slaves_count(), 1)
            bob_access_type = self.chain_manager.get_slave_pk_access_type(alice.address, bob.pk)
            self.assertEqual(bob_access_type.access_type, 0)

            # Add fork block on genesis block
            with patch('qrl.core.misc.ntp.getTime') as time_mock:
                time_mock.return_value = 1715270948  # Very high to get an easy difficulty
                fork_block = Block.create(dev_config=config.dev,
                                          block_number=1,
                                          prev_headerhash=self.genesis_block.headerhash,
                                          prev_timestamp=self.genesis_block.timestamp,
                                          transactions=[],
                                          miner_address=bob.address,
                                          seed_height=None,
                                          seed_hash=None)

                fork_block.set_nonces(config.dev, 4, 0)
                # Uncomment only to determine the correct mining_nonce of above blocks
                # from qrl.core.PoWValidator import PoWValidator
                # while not PoWValidator().validate_mining_nonce(self.state, fork_block.blockheader, False):
                #     fork_block.set_nonces(fork_block.mining_nonce + 1)
                #     print(fork_block.mining_nonce)
                self.assertTrue(fork_block.validate(self.chain_manager, {}))
                result = self.chain_manager.add_block(fork_block)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)

            fork_block = Block.get_block(self.state, fork_block.headerhash)
            self.assertIsNotNone(fork_block)

            # Add block_2 on fork_block.
            with patch('qrl.core.misc.ntp.getTime') as time_mock:
                time_mock.return_value = 1815270948  # Very high to get an easy difficulty
                block_2 = fork_block.create(dev_config=config.dev,
                                            block_number=2,
                                            prev_headerhash=fork_block.headerhash,
                                            prev_timestamp=fork_block.timestamp,
                                            transactions=[],
                                            miner_address=bob.address,
                                            seed_height=None,
                                            seed_hash=None)

                block_2.set_nonces(config.dev, 1, 0)
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
            bob_access_type = self.chain_manager.get_slave_pk_access_type(alice.address, bob.pk)
            self.assertIsNone(bob_access_type)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block2(self, time_mock):
        """
        Features Tested
        - Multi Sig Create, Spend & Vote Txn
        - Vote on a multi sig spend

        Expectation
        - Multi Sig Spend transaction must be executed as it has received sufficient vote and reached to threshold.

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
            #     block_1.set_nonces(block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 1)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[transfer_transaction],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_2.blockheader, False):
            #     block_2.set_nonces(block_2.mining_nonce + 1)
            #     print(block_2.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_2)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 2)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[multi_sig_spend],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_3.blockheader, config.dev, False):
            #     block_3.set_nonces(config.dev, block_3.mining_nonce + 1)
            #     print(block_3.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_3)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(4))
            block_4 = Block.create(dev_config=config.dev,
                                   block_number=4,
                                   prev_headerhash=block_3.headerhash,
                                   prev_timestamp=block_3.timestamp,
                                   transactions=[multi_sig_vote1],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_4.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_4.blockheader, config.dev, False):
            #     block_4.set_nonces(config.dev, block_4.mining_nonce + 1)
            #     print(block_4.mining_nonce)
            self.assertTrue(block_4.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_4)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_4)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(5))
            block_5 = Block.create(dev_config=config.dev,
                                   block_number=5,
                                   prev_headerhash=block_4.headerhash,
                                   prev_timestamp=block_4.timestamp,
                                   transactions=[multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_5.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_5.blockheader, config.dev, False):
            #     block_5.set_nonces(config.dev, block_5.mining_nonce + 1)
            #     print(block_5.mining_nonce)
            self.assertTrue(block_5.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_5)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_5)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance, 59 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + block_1.fee_reward +
                             block_2.block_reward + block_2.fee_reward +
                             block_3.block_reward + block_3.fee_reward +
                             block_4.block_reward + block_4.fee_reward +
                             block_5.block_reward + block_5.fee_reward +
                             5)
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta) + 10)
            self.assertEqual(multi_sig_address_state.balance, 40 * int(config.dev.shor_per_quanta) - 15)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block3(self, time_mock):
        """
        Features Tested
        - Multi Sig Create, Spend & Vote Txn
        - Vote on an expired multi sig spend

        Expectation
        - Block including the vote for multi sig vote txn must be rejected due to failure in validation.
        - Multi Sig Spend transaction must not have executed as it expired without sufficient vote reaching threshold.

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=4,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
            #     block_1.set_nonces(block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 1)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[transfer_transaction],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_2.blockheader, False):
            #     block_2.set_nonces(block_2.mining_nonce + 1)
            #     print(block_2.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_2)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 2)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[multi_sig_spend],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_3.blockheader, False):
            #     block_3.set_nonces(block_3.mining_nonce + 1)
            #     print(block_3.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_3)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(4))
            block_4 = Block.create(dev_config=config.dev,
                                   block_number=4,
                                   prev_headerhash=block_3.headerhash,
                                   prev_timestamp=block_3.timestamp,
                                   transactions=[multi_sig_vote1],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_4.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_4.blockheader, False):
            #     block_4.set_nonces(block_4.mining_nonce + 1)
            #     print(block_4.mining_nonce)
            self.assertTrue(block_4.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_4)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_4)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(5))
            block_5 = Block.create(dev_config=config.dev,
                                   block_number=5,
                                   prev_headerhash=block_4.headerhash,
                                   prev_timestamp=block_4.timestamp,
                                   transactions=[multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_5.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not self.chain_manager.validate_mining_nonce(block_5.blockheader, False):
            #     block_5.set_nonces(block_5.mining_nonce + 1)
            #     print(block_5.mining_nonce)
            self.assertTrue(block_5.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_5)

            # Block rejected as is includes vote for the expired multi sig spend txn.
            self.assertFalse(result)
            self.assertEqual(self.chain_manager.last_block, block_4)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance, 59 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + block_1.fee_reward +
                             block_2.block_reward + block_2.fee_reward +
                             block_3.block_reward + block_3.fee_reward +
                             block_4.block_reward + block_4.fee_reward)
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state.balance, 40 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block4(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation with lattice transctions

        Expectation
        - Block 1 and 2 must be added as both of them have valid lattice transaction
        - Block 3 must not be added, as it includes a lattice txn adding duplicate public keys

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            lattice_pk = LatticeTransaction.create(pk1=b'alice_pk1',
                                                   pk2=b'alice_pk2',
                                                   pk3=b'alice_pk3',
                                                   fee=5,
                                                   xmss_pk=alice_xmss.pk)
            lattice_pk.sign(alice_xmss)
            lattice_pk.pbdata.nonce = 1

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[lattice_pk],
                                   miner_address=bob_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 1, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)

            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) - 5)
            self.assertEqual(alice_addr_state.lattice_pk_count(), 1)
            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + 5)

            lattice_pk2 = LatticeTransaction.create(pk1=b'alice_pk11',
                                                    pk2=b'alice_pk12',
                                                    pk3=b'alice_pk13',
                                                    fee=5,
                                                    xmss_pk=alice_xmss.pk)
            lattice_pk2.sign(alice_xmss)
            lattice_pk2.pbdata.nonce = 2

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[lattice_pk2],
                                   miner_address=bob_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 10, 0)

            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_2)

            # Duplicate set of public keys in lattice transaction
            lattice_pk3 = LatticeTransaction.create(pk1=b'alice_pk11',
                                                    pk2=b'alice_pk12',
                                                    pk3=b'alice_pk13',
                                                    fee=5,
                                                    xmss_pk=alice_xmss.pk)
            lattice_pk3.sign(alice_xmss)
            lattice_pk3.pbdata.nonce = 3

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[lattice_pk3],
                                   miner_address=bob_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 1, 0)

            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)

            self.assertFalse(result)
            self.assertEqual(self.chain_manager.last_block, block_2)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block5(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn, transfer txn, multisig spend txn
          & multi sig vote are added into same block

        Expectation
        - Block must have been added
        - multi_sig_spend txn must not be executed as threshold has not reached

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction,
                                                 multi_sig_spend, multi_sig_vote1],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertFalse(vote_stats.executed)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block6(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn, transfer txn, multisig spend txn,
          two multisig vote txns are added into same block.
        - Behavior of Rollback
        - Transaction storage in State
        - OTS index usage before and after rollback

        Expectation
        - Block must have been added
        - multi_sig_spend txn must be executed as threshold has reached
        - Rollback must happen successfully
        - Used OTS indexes after rollback must be found as unused
        - Transaction must be found in State before roll back
        - Transaction must not be found in State after roll back

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend,
                                                 multi_sig_vote1, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance, 59 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + block_1.fee_reward +
                             multi_sig_spend.amounts[1])
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) + multi_sig_spend.amounts[0])
            self.assertEqual(multi_sig_address_state.balance,
                             40 * int(config.dev.shor_per_quanta) - multi_sig_spend.total_amount)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            # Check Txns in State
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertIsNotNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_create.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction.pbdata)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            # Rollback state to genesis block
            self.chain_manager._rollback(self.genesis_block.headerhash)

            # Post Rollback tests
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertIsNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertIsNone(tx_meta_data)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 0)
            self.assertEqual(random_addr_state.nonce, 0)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state, None)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertFalse(result)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block7(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn, transfer txn, multisig spend txn,
          three multisig vote txns are added into same block.
          First, MultiSig vote txn signed by Alice to add vote
          Second, MultiSig vote txn signed by Bob to add vote
          Third, MultiSig vote txn signed by Alice to unvote
        - Behavior of Rollback
        - Transaction storage in State
        - OTS index usage before and after rollback

        Expectation
        - Block must have been added.
        - The order of transaction in block is Vote1, Vote3, Vote2, so threshold is not reached.
        - multi_sig_spend transaction must not execute.
        - Rollback must happen successfully
        - Used OTS indexes after rollback must be found as unused
        - Transaction must be found in State before roll back
        - Transaction must not be found in State after roll back

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            multi_sig_vote3 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=True,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote3.sign(alice_xmss)
            multi_sig_vote3.pbdata.nonce = 4

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend,
                                                 multi_sig_vote1, multi_sig_vote3, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance, 59 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + block_1.fee_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state.balance,
                             40 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            # Check Txns in State
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertIsNotNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_create.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            multi_sig_vote3.set_prev_tx_hash(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote3.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction.pbdata)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertTrue(result)

            # Rollback state to genesis block
            self.chain_manager._rollback(self.genesis_block.headerhash)

            # Post Rollback tests
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertIsNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertIsNone(tx_meta_data)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 0)
            self.assertEqual(random_addr_state.nonce, 0)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state, None)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertFalse(result)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block8(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn, transfer txn, multisig spend txn,
          three multisig vote txns are added into same block.
          First, MultiSig vote txn signed by Alice to add vote
          Second, MultiSig vote txn signed by Bob to add vote
          Third, MultiSig vote txn signed by Alice to unvote

        Expectation
        - Block must not be added.
        - The order of transaction in block is Vote1, Vote2, Vote3 so threshold is reached,
          thus Multi Sig Vote3 becomes invalid as unvote txn found after threshold reached.
          so the block becomes invalid and rejected.

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            multi_sig_vote3 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=True,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote3.sign(alice_xmss)
            multi_sig_vote3.pbdata.nonce = 4

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend,
                                                 multi_sig_vote1, multi_sig_vote2, multi_sig_vote3],
                                   miner_address=alice_xmss.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_1.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertFalse(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertIsNone(vote_stats)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta))
            self.assertIsNone(multi_sig_address_state)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block9(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn, transfer txn, multisig spend txn,
          two multisig vote txns are added into same block.

        Expectation
        - Block must not be added, as it includes duplicate multi sig vote txn.

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote2.sign(alice_xmss)
            multi_sig_vote2.pbdata.nonce = 4

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend,
                                                 multi_sig_vote1, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_1.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertFalse(result)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block10(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when two multi sig spend transactions are made, such that
          the last multi sig spend transaction gets enough vote but multi sig address, doesn't
          have enough fund for the last multi sig spend transaction.
        - Behavior of Rollback
        - Transaction storage in State
        - OTS index usage before and after rollback

        Expectation
        - Both blocks must be added.
        - multi_sig_spend1 must be executed at block 1
        - multi_sig_spend2 must have received enough vote at block 2,
          but must not execute due to lack of funds.
        - Rollback must happen successfully
        - Used OTS indexes after rollback must be found as unused
        - Transaction must be found in State before roll back
        - Transaction must not be found in State after roll back

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend1 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[20, 15],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend1.sign(alice_xmss)
            multi_sig_spend1.pbdata.nonce = 2

            multi_sig_spend2 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[10, 10],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend2.sign(alice_xmss)
            multi_sig_spend2.pbdata.nonce = 3

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 4

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            multi_sig_vote3 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote3.sign(alice_xmss)
            multi_sig_vote3.pbdata.nonce = 5

            multi_sig_vote4 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote4.sign(bob_xmss)
            multi_sig_vote4.pbdata.nonce = 3

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend1,
                                                 multi_sig_spend2, multi_sig_vote1, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction.fee -
                             transfer_transaction.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction.total_amount -
                             multi_sig_spend1.total_amount)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[multi_sig_vote3, multi_sig_vote4],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction.fee -
                             transfer_transaction.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction.total_amount -
                             multi_sig_spend1.total_amount)

            # Check Txns in State
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertIsNotNone(vote_stats)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertIsNotNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_create.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote3.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote4.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction.pbdata)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertTrue(result)

            # Rollback state to genesis block
            self.chain_manager._rollback(self.genesis_block.headerhash)

            # Post Rollback tests
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertIsNone(vote_stats)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertIsNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend2.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertIsNone(tx_meta_data)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 0)
            self.assertEqual(random_addr_state.nonce, 0)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(multi_sig_address_state, None)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertFalse(result)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block11(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when two multi sig spend transactions are made, such that
          the last multi sig spend transaction gets enough vote but multi sig address, doesn't
          have enough fund for the last multi sig spend transaction.
          Then the transaction in block 3 sends more funds to Multi Sig Address, making sufficient funds.
          Although to execute the multi_sig_spend2 txn, it needs to be re checked by executing some
          vote txn. So in block 4, a multi_sig_vote txn is added to unvote it.
          In block 5, a multi_sig_vote txn is added to add vote again, reaching threshold.
        - Behavior of Rollback
        - Transaction storage in State
        - OTS index usage before and after rollback

        Expectation
        - Both blocks must be added.
        - multi_sig_spend1 must be executed at block 1
        - multi_sig_spend2 must have received enough vote at block 2,
          but must not execute due to lack of funds.
        - In block 5, when re voted there will be enough funds in multi sig address, so the
          multi_sig_spend2 txn must have been executed.
        - Rollback must happen successfully
        - Used OTS indexes after rollback must be found as unused
        - Transaction must be found in State before roll back
        - Transaction must not be found in State after roll back


        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction1 = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                               amounts=[40],
                                                               message_data=None,
                                                               fee=1 * config.dev.shor_per_quanta,
                                                               xmss_pk=bob_xmss.pk)
            transfer_transaction1._data.nonce = 1
            transfer_transaction1.sign(bob_xmss)
            self.assertTrue(transfer_transaction1.validate_or_raise(True))

            multi_sig_spend1 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[20, 15],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend1.sign(alice_xmss)
            multi_sig_spend1.pbdata.nonce = 2

            multi_sig_spend2 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[10, 10],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend2.sign(alice_xmss)
            multi_sig_spend2.pbdata.nonce = 3

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 4

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            multi_sig_vote3 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote3.sign(alice_xmss)
            multi_sig_vote3.pbdata.nonce = 5

            multi_sig_vote4 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote4.sign(bob_xmss)
            multi_sig_vote4.pbdata.nonce = 3

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction1, multi_sig_spend1,
                                                 multi_sig_spend2, multi_sig_vote1, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount -
                             multi_sig_spend1.total_amount)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[multi_sig_vote3, multi_sig_vote4],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount -
                             multi_sig_spend1.total_amount)

            transfer_transaction2 = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                               amounts=[40],
                                                               message_data=None,
                                                               fee=1 * config.dev.shor_per_quanta,
                                                               xmss_pk=bob_xmss.pk)
            transfer_transaction2._data.nonce = 4
            transfer_transaction2.sign(bob_xmss)
            self.assertTrue(transfer_transaction2.validate_or_raise(True))

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[transfer_transaction2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_3.blockheader, config.dev, False):
            #     block_3.set_nonces(config.dev, block_3.mining_nonce + 1)
            #     print(block_3.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount)

            multi_sig_vote5 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=True,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote5.sign(bob_xmss)
            multi_sig_vote5.pbdata.nonce = 5

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(4))
            block_4 = Block.create(dev_config=config.dev,
                                   block_number=4,
                                   prev_headerhash=block_3.headerhash,
                                   prev_timestamp=block_3.timestamp,
                                   transactions=[multi_sig_vote5],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_4.set_nonces(config.dev, 4, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_4.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_4)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount -
                             multi_sig_vote5.fee)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward +
                             block_4.fee_reward +
                             block_4.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount)

            multi_sig_vote6 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote6.sign(bob_xmss)
            multi_sig_vote6.pbdata.nonce = 6

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(5))
            block_5 = Block.create(dev_config=config.dev,
                                   block_number=5,
                                   prev_headerhash=block_4.headerhash,
                                   prev_timestamp=block_4.timestamp,
                                   transactions=[multi_sig_vote6],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_5.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_5.blockheader, config.dev, False):
            #     block_5.set_nonces(config.dev, block_5.mining_nonce + 1)
            #     print(block_5.mining_nonce)
            self.assertTrue(block_5.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_5)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount -
                             multi_sig_vote5.fee -
                             multi_sig_vote6.fee)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             multi_sig_spend2.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward +
                             block_4.fee_reward +
                             block_4.block_reward +
                             block_5.fee_reward +
                             block_5.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0] +
                             multi_sig_spend2.amounts[1])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount -
                             multi_sig_spend2.total_amount)

            # Check Txns in State
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertIsNotNone(vote_stats)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertIsNotNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_create.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote3.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote4.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote5.txhash)
            multi_sig_vote5.set_prev_tx_hash(multi_sig_vote4.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote5.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote6.txhash)
            multi_sig_vote6.set_prev_tx_hash(multi_sig_vote5.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote6.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction2.pbdata)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote5.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote6.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction2.ots_key)
            self.assertTrue(result)

            # Rollback state to genesis block
            self.assertTrue(self.chain_manager._rollback(self.genesis_block.headerhash))

            # Post Rollback tests
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertIsNone(vote_stats)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertIsNone(vote_stats)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend2.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote5.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote6.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction1.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction2.txhash)
            self.assertIsNone(tx_meta_data)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 0)
            self.assertEqual(random_addr_state.nonce, 0)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta))

            self.assertEqual(multi_sig_address_state, None)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote5.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote6.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction1.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction2.ots_key)
            self.assertFalse(result)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block12(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation after expiry.

        Expectation
        - Block 1 must be added, as it includes valid transactions.
        - Block 2 must be added.
        - Block 3 must fail as it includes vote for an expired multi_sig_spend transaction.
        - multi_sig_spend txn must not be executed as threshold has not reached.

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=2,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_unvote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                    unvote=False,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_unvote1.sign(alice_xmss)
            multi_sig_unvote1.pbdata.nonce = 4

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction,
                                                 multi_sig_spend, multi_sig_vote1],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 1, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 1, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_2.blockheader, config.dev, False):
            #     block_2.set_nonces(config.dev, block_2.mining_nonce + 1)
            #     print(block_2.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)
            self.assertTrue(result)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            # Trying to add block_3 with an vote txn for an expired multi_sig_spend txn to meet threshold
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_3.blockheader, config.dev, False):
            #     block_3.set_nonces(config.dev, block_3.mining_nonce + 1)
            #     print(block_3.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)
            self.assertFalse(result)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            # Trying to add block_3 with an unvote txn for an expired multi_sig_spend txn
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[multi_sig_unvote1],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 1, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_3.blockheader, config.dev, False):
            #     block_3.set_nonces(config.dev, block_3.mining_nonce + 1)
            #     print(block_3.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)
            self.assertFalse(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend.txhash)
            self.assertFalse(vote_stats.executed)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block13(self, time_mock):
        """
        Features Tested
        - Slave transactions
        - Transfer Transaction made by slave address
        - Rollback of slave transaction

        Expectation
        - block_1 must be accepted as all transactions are valid
        - block_2 must be rejected as the slave transaction includes existing slave address
          associated with master address
        - After rollback, slaves meta data containing access type, must not be found in the state

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed1 = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                             "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            extended_seed2 = "01040097cbf736e725a5da3ccbdb78688f9261d54a9d752108f" \
                             "c331f51e46aca23757d42d49f9aeea3ba2818ed378e755b6c17"
            random_xmss1 = XMSS.from_extended_seed(hstr2bin(extended_seed1))
            random_xmss2 = XMSS.from_extended_seed(hstr2bin(extended_seed2))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            slave_txn1 = SlaveTransaction.create(slave_pks=[random_xmss1.pk, random_xmss2.pk],
                                                 access_types=[0, 0],
                                                 fee=5,
                                                 xmss_pk=alice_xmss.pk)
            slave_txn1.sign(alice_xmss)
            slave_txn1.pbdata.nonce = 1

            transfer_txn = TransferTransaction.create(addrs_to=[random_xmss1.address],
                                                      amounts=[40 * int(config.dev.shor_per_quanta)],
                                                      message_data=None,
                                                      fee=1 * config.dev.shor_per_quanta,
                                                      xmss_pk=random_xmss2.pk,
                                                      master_addr=alice_xmss.address)
            transfer_txn.sign(random_xmss2)
            transfer_txn.pbdata.nonce = 1

            slave_txn2 = SlaveTransaction.create(slave_pks=[random_xmss1.pk],
                                                 access_types=[0],
                                                 fee=5,
                                                 xmss_pk=alice_xmss.pk)
            slave_txn2.sign(alice_xmss)
            slave_txn2.pbdata.nonce = 2

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[slave_txn1, transfer_txn],
                                   miner_address=alice_xmss.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_1.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state1 = self.chain_manager.get_optimized_address_state(random_xmss1.address)
            random_addr_state2 = self.chain_manager.get_optimized_address_state(random_xmss2.address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + block_1.fee_reward -
                             slave_txn1.fee -
                             transfer_txn.fee -
                             transfer_txn.total_amount)
            self.assertEqual(random_addr_state1.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             transfer_txn.amounts[0])
            self.assertEqual(random_addr_state2.balance, 100 * int(config.dev.shor_per_quanta))

            slave_metadata = self.chain_manager.get_slave_pk_access_type(alice_addr_state.address, random_xmss1.pk)
            self.assertEqual(slave_metadata.access_type, 0)

            slave_metadata = self.chain_manager.get_slave_pk_access_type(alice_addr_state.address, random_xmss2.pk)
            self.assertEqual(slave_metadata.access_type, 0)

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 1)
            self.assertEqual(random_addr_state1.nonce, 0)
            self.assertEqual(random_addr_state2.nonce, 1)

            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[slave_txn2],
                                   miner_address=alice_xmss.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_2.set_nonces(config.dev, 1, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_2.blockheader, config.dev, False):
            #     block_2.set_nonces(config.dev, block_2.mining_nonce + 1)
            #     print(block_2.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)

            self.assertFalse(result)

            self.assertTrue(self.chain_manager._rollback(self.genesis_block.headerhash))

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state1 = self.chain_manager.get_optimized_address_state(random_xmss1.address)
            random_addr_state2 = self.chain_manager.get_optimized_address_state(random_xmss2.address)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state1.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state2.balance, 100 * int(config.dev.shor_per_quanta))

            slave_metadata = self.chain_manager.get_slave_pk_access_type(alice_addr_state.address, random_xmss1.pk)
            self.assertIsNone(slave_metadata)

            slave_metadata = self.chain_manager.get_slave_pk_access_type(alice_addr_state.address, random_xmss2.pk)
            self.assertIsNone(slave_metadata)

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 0)
            self.assertEqual(random_addr_state1.nonce, 0)
            self.assertEqual(random_addr_state2.nonce, 0)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block14(self, time_mock):
        """
        Features Tested
        - Transfer Transaction made by slave address which is not associated by the master address

        Expectation
        - block_1 must be rejected as slave is not associated with master address

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed1 = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                             "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            extended_seed2 = "01040097cbf736e725a5da3ccbdb78688f9261d54a9d752108f" \
                             "c331f51e46aca23757d42d49f9aeea3ba2818ed378e755b6c17"
            random_xmss1 = XMSS.from_extended_seed(hstr2bin(extended_seed1))
            random_xmss2 = XMSS.from_extended_seed(hstr2bin(extended_seed2))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)

            transfer_txn = TransferTransaction.create(addrs_to=[random_xmss1.address],
                                                      amounts=[40 * int(config.dev.shor_per_quanta)],
                                                      message_data=None,
                                                      fee=1 * config.dev.shor_per_quanta,
                                                      xmss_pk=random_xmss2.pk,
                                                      master_addr=alice_xmss.address)
            transfer_txn.sign(random_xmss2)
            transfer_txn.pbdata.nonce = 1

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[transfer_txn],
                                   miner_address=alice_xmss.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_1.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertFalse(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertFalse(result)
            self.assertEqual(self.chain_manager.last_block, self.genesis_block)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state1 = self.chain_manager.get_optimized_address_state(random_xmss1.address)
            random_addr_state2 = self.chain_manager.get_optimized_address_state(random_xmss2.address)

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state1.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state2.balance, 100 * int(config.dev.shor_per_quanta))

            self.assertEqual(bob_addr_state.nonce, 0)
            self.assertEqual(alice_addr_state.nonce, 0)
            self.assertEqual(random_addr_state1.nonce, 0)
            self.assertEqual(random_addr_state2.nonce, 0)

            slave_metadata = self.chain_manager.get_slave_pk_access_type(alice_addr_state.address, random_xmss1.pk)
            self.assertIsNone(slave_metadata)

            slave_metadata = self.chain_manager.get_slave_pk_access_type(alice_addr_state.address, random_xmss2.pk)
            self.assertIsNone(slave_metadata)

    @set_default_balance_size()
    @patch('qrl.core.misc.ntp.getTime')
    def test_add_block15(self, time_mock):
        """
        Features Tested
        - Behavior of Slave txn when duplicate slave transaction are added into a single block

        Expectation
        - block_1 must be rejected as the slave transaction includes existing slave address
          associated with master address

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed1 = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                             "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            extended_seed2 = "01040097cbf736e725a5da3ccbdb78688f9261d54a9d752108f" \
                             "c331f51e46aca23757d42d49f9aeea3ba2818ed378e755b6c17"
            random_xmss1 = XMSS.from_extended_seed(hstr2bin(extended_seed1))
            random_xmss2 = XMSS.from_extended_seed(hstr2bin(extended_seed2))
            alice_xmss = get_alice_xmss(4)
            slave_txn1 = SlaveTransaction.create(slave_pks=[random_xmss1.pk, random_xmss2.pk],
                                                 access_types=[0, 0],
                                                 fee=5,
                                                 xmss_pk=alice_xmss.pk)
            slave_txn1.sign(alice_xmss)
            slave_txn1.pbdata.nonce = 1

            slave_txn2 = SlaveTransaction.create(slave_pks=[random_xmss1.pk],
                                                 access_types=[0],
                                                 fee=5,
                                                 xmss_pk=alice_xmss.pk)
            slave_txn2.sign(alice_xmss)
            slave_txn2.pbdata.nonce = 2

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[slave_txn1, slave_txn2],
                                   miner_address=alice_xmss.address,
                                   seed_height=None,
                                   seed_hash=None)
            block_1.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertFalse(result)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_rollback(self, time_mock):
        # Test that adding block for multi sig spend with multi sig vote txn
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 129, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_1.blockheader, False):
            #     block_1.set_nonces(block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_1)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 1)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[transfer_transaction],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not PoWValidator().validate_mining_nonce(self.state, block_2.blockheader, False):
            #     block_2.set_nonces(block_2.mining_nonce + 1)
            #     print(block_2.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_2)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 2)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[multi_sig_spend],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_3.blockheader, config.dev, False):
            #     block_3.set_nonces(config.dev, block_3.mining_nonce + 1)
            #     print(block_3.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_3)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(4))
            block_4 = Block.create(dev_config=config.dev,
                                   block_number=4,
                                   prev_headerhash=block_3.headerhash,
                                   prev_timestamp=block_3.timestamp,
                                   transactions=[multi_sig_vote1],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_4.set_nonces(config.dev, 4, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_4.blockheader, config.dev, False):
            #     block_4.set_nonces(config.dev, block_4.mining_nonce + 1)
            #     print(block_4.mining_nonce)
            self.assertTrue(block_4.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_4)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_4)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(5))
            block_5 = Block.create(dev_config=config.dev,
                                   block_number=5,
                                   prev_headerhash=block_4.headerhash,
                                   prev_timestamp=block_4.timestamp,
                                   transactions=[multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_5.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not self.chain_manager.validate_mining_nonce(block_5.blockheader, False):
            #     block_5.set_nonces(block_5.mining_nonce + 1)
            #     print(block_5.mining_nonce)
            self.assertTrue(block_5.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_5)

            self.assertTrue(result)
            self.assertEqual(self.chain_manager.last_block, block_5)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance, 59 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             block_1.block_reward + block_1.fee_reward +
                             block_2.block_reward + block_2.fee_reward +
                             block_3.block_reward + block_3.fee_reward +
                             block_4.block_reward + block_4.fee_reward +
                             block_5.block_reward + block_5.fee_reward +
                             5)
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta) + 10)
            self.assertEqual(multi_sig_address_state.balance, 40 * int(config.dev.shor_per_quanta) - 15)
            self.assertEqual(multi_sig_address_state.transaction_hash_count(), 3)

            self.chain_manager._rollback(self.genesis_block.headerhash)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)

            self.assertIsNone(MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db, multi_sig_address))

            self.assertEqual(bob_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(alice_addr_state.balance, 100 * int(config.dev.shor_per_quanta))
            self.assertEqual(random_addr_state.balance, 100 * int(config.dev.shor_per_quanta))

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_rollback2(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when two multi sig spend transactions are made, such that
          the last multi sig spend transaction gets enough vote but multi sig address, doesn't
          have enough fund for the last multi sig spend transaction.
        - Behavior of Rollback for block number 2
        - Transaction storage in State
        - OTS index usage before and after rollback

        Expectation
        - Both blocks must be added.
        - multi_sig_spend1 must be executed at block 1
        - multi_sig_spend2 must have received enough vote at block 2,
          but must not execute due to lack of funds.
        - Rollback must happen successfully
        - multi_sig_vote3 and multi_sig_vote4 must be found in the state before rollback
        - multi_sig_vote3 and multi_sig_vote4 must be deleted from the state after the rollback
        - Used OTS indexes for multi_sig_vote3 and multi_sig_vote4 after rollback must be found as unused

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend1 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[20, 15],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend1.sign(alice_xmss)
            multi_sig_spend1.pbdata.nonce = 2

            multi_sig_spend2 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[10, 10],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend2.sign(alice_xmss)
            multi_sig_spend2.pbdata.nonce = 3

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 4

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            multi_sig_vote3 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote3.sign(alice_xmss)
            multi_sig_vote3.pbdata.nonce = 5

            multi_sig_vote4 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote4.sign(bob_xmss)
            multi_sig_vote4.pbdata.nonce = 3

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend1,
                                                 multi_sig_spend2, multi_sig_vote1, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction.fee -
                             transfer_transaction.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction.total_amount -
                             multi_sig_spend1.total_amount)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[multi_sig_vote3, multi_sig_vote4],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction.fee -
                             transfer_transaction.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction.total_amount -
                             multi_sig_spend1.total_amount)

            # Check Txns in State
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertIsNotNone(vote_stats)
            self.assertTrue(vote_stats.executed)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertIsNotNone(vote_stats)
            self.assertFalse(vote_stats.executed)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_create.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote3.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote4.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction.pbdata)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertTrue(result)

            # Rollback state to block number 1
            self.chain_manager._rollback(block_1.headerhash)

            # Post Rollback tests
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertIsNone(tx_meta_data)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertIsNone(tx_meta_data)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)

            self.assertEqual(bob_addr_state.nonce, 2)
            self.assertEqual(alice_addr_state.nonce, 4)
            self.assertEqual(random_addr_state.nonce, 0)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction.total_amount -
                             transfer_transaction.fee)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertFalse(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction.ots_key)
            self.assertTrue(result)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_roll_back3(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when two multi sig spend transactions are made, such that
          the last multi sig spend transaction gets enough vote but multi sig address, doesn't
          have enough fund for the last multi sig spend transaction.
          Then the transaction in block 3 sends more funds to Multi Sig Address, making sufficient funds.
          Although to execute the multi_sig_spend2 txn, it needs to be re checked by executing some
          vote txn. So in block 4, a multi_sig_vote txn is added to unvote it.
          In block 5, a multi_sig_vote txn is added to add vote again, reaching threshold.
        - Behavior of Rollback
        - Transaction storage in State
        - OTS index usage before and after rollback

        Expectation
        - Both blocks must be added.
        - multi_sig_spend1 must be executed at block 1
        - multi_sig_spend2 must have received enough vote at block 2,
          but must not execute due to lack of funds.
        - In block 5, when re voted there will be enough funds in multi sig address, so the
          multi_sig_spend2 txn must have been executed.
        - Rollback must happen successfully
        - Used OTS indexes after rollback must be found as unused
        - Transaction must be found in State before roll back
        - Transaction must not be found in State after roll back


        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=8,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction1 = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                               amounts=[40],
                                                               message_data=None,
                                                               fee=1 * config.dev.shor_per_quanta,
                                                               xmss_pk=bob_xmss.pk)
            transfer_transaction1._data.nonce = 1
            transfer_transaction1.sign(bob_xmss)
            self.assertTrue(transfer_transaction1.validate_or_raise(True))

            multi_sig_spend1 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[20, 15],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend1.sign(alice_xmss)
            multi_sig_spend1.pbdata.nonce = 2

            multi_sig_spend2 = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                    addrs_to=[random_xmss.address, alice_xmss.address],
                                                    amounts=[10, 10],
                                                    expiry_block_number=100,
                                                    fee=0,
                                                    xmss_pk=alice_xmss.pk)
            multi_sig_spend2.sign(alice_xmss)
            multi_sig_spend2.pbdata.nonce = 3

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 4

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend1.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2

            multi_sig_vote3 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote3.sign(alice_xmss)
            multi_sig_vote3.pbdata.nonce = 5

            multi_sig_vote4 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote4.sign(bob_xmss)
            multi_sig_vote4.pbdata.nonce = 3

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction1, multi_sig_spend1,
                                                 multi_sig_spend2, multi_sig_vote1, multi_sig_vote2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 2, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount -
                             multi_sig_spend1.total_amount)

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(2))
            block_2 = Block.create(dev_config=config.dev,
                                   block_number=2,
                                   prev_headerhash=block_1.headerhash,
                                   prev_timestamp=block_1.timestamp,
                                   transactions=[multi_sig_vote3, multi_sig_vote4],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_2.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_2.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_2)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount -
                             multi_sig_spend1.total_amount)

            transfer_transaction2 = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                               amounts=[40],
                                                               message_data=None,
                                                               fee=1 * config.dev.shor_per_quanta,
                                                               xmss_pk=bob_xmss.pk)
            transfer_transaction2._data.nonce = 4
            transfer_transaction2.sign(bob_xmss)
            self.assertTrue(transfer_transaction2.validate_or_raise(True))

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(3))
            block_3 = Block.create(dev_config=config.dev,
                                   block_number=3,
                                   prev_headerhash=block_2.headerhash,
                                   prev_timestamp=block_2.timestamp,
                                   transactions=[transfer_transaction2],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_3.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_3.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_3)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount)

            multi_sig_vote5 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=True,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote5.sign(bob_xmss)
            multi_sig_vote5.pbdata.nonce = 5

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(4))
            block_4 = Block.create(dev_config=config.dev,
                                   block_number=4,
                                   prev_headerhash=block_3.headerhash,
                                   prev_timestamp=block_3.timestamp,
                                   transactions=[multi_sig_vote5],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_4.set_nonces(config.dev, 4, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_4.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_4)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount -
                             multi_sig_vote5.fee)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward +
                             block_4.fee_reward +
                             block_4.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount)

            multi_sig_vote6 = MultiSigVote.create(shared_key=multi_sig_spend2.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote6.sign(bob_xmss)
            multi_sig_vote6.pbdata.nonce = 6

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(5))
            block_5 = Block.create(dev_config=config.dev,
                                   block_number=5,
                                   prev_headerhash=block_4.headerhash,
                                   prev_timestamp=block_4.timestamp,
                                   transactions=[multi_sig_vote6],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_5.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_5.blockheader, config.dev, False):
            #     block_5.set_nonces(config.dev, block_5.mining_nonce + 1)
            #     print(block_5.mining_nonce)
            self.assertTrue(block_5.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_5)
            self.assertTrue(result)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertTrue(vote_stats.executed)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount -
                             multi_sig_vote5.fee -
                             multi_sig_vote6.fee)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             multi_sig_spend2.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward +
                             block_4.fee_reward +
                             block_4.block_reward +
                             block_5.fee_reward +
                             block_5.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0] +
                             multi_sig_spend2.amounts[1])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount -
                             multi_sig_spend2.total_amount)

            # Check Txns in State
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertIsNotNone(vote_stats)
            self.assertTrue(vote_stats.executed)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertIsNotNone(vote_stats)
            self.assertTrue(vote_stats.executed)
            self.assertEqual(vote_stats.total_weight, 10)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_create.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_create.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_spend2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_spend2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote2.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote3.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote3.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote4.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote4.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote5.txhash)
            multi_sig_vote5.set_prev_tx_hash(multi_sig_vote4.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote5.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote6.txhash)
            multi_sig_vote6.set_prev_tx_hash(multi_sig_vote5.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, multi_sig_vote6.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction1.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction1.pbdata)

            tx_meta_data = self.chain_manager.get_tx_metadata(transfer_transaction2.txhash)
            self.assertEqual(tx_meta_data[0].pbdata, transfer_transaction2.pbdata)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)
            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_create.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_spend2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote2.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(alice_addr_state.address, multi_sig_vote3.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote4.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote5.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote6.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction1.ots_key)
            self.assertTrue(result)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, transfer_transaction2.ots_key)
            self.assertTrue(result)

            # Rollback state to block number 4
            self.assertTrue(self.chain_manager._rollback(block_4.headerhash))

            self.assertEqual(self.chain_manager.last_block.block_number, block_4.block_number)

            # Post Rollback tests
            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)
            self.assertEqual(vote_stats.total_weight, 4)

            tx_meta_data = self.chain_manager.get_tx_metadata(multi_sig_vote6.txhash)
            self.assertIsNone(tx_meta_data)

            bob_addr_state = self.chain_manager.get_optimized_address_state(bob_xmss.address)
            alice_addr_state = self.chain_manager.get_optimized_address_state(alice_xmss.address)
            random_addr_state = self.chain_manager.get_optimized_address_state(random_xmss.address)
            multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self.state._db,
                                                                                                  multi_sig_address)

            self.assertEqual(bob_addr_state.nonce, 5)
            self.assertEqual(alice_addr_state.nonce, 5)
            self.assertEqual(random_addr_state.nonce, 0)

            self.assertEqual(bob_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) -
                             transfer_transaction1.fee -
                             transfer_transaction1.total_amount -
                             transfer_transaction2.fee -
                             transfer_transaction2.total_amount -
                             multi_sig_vote5.fee)
            self.assertEqual(alice_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[1] +
                             block_1.fee_reward +
                             block_1.block_reward +
                             block_2.fee_reward +
                             block_2.block_reward +
                             block_3.fee_reward +
                             block_3.block_reward +
                             block_4.fee_reward +
                             block_4.block_reward)
            self.assertEqual(random_addr_state.balance,
                             100 * int(config.dev.shor_per_quanta) +
                             multi_sig_spend1.amounts[0])

            self.assertIsNotNone(multi_sig_address_state)
            self.assertEqual(multi_sig_address_state.balance,
                             transfer_transaction1.total_amount +
                             transfer_transaction2.total_amount -
                             multi_sig_spend1.total_amount)

            # Check OTS key usage
            p = PaginatedBitfield(False, self.state._db)

            result = p.load_bitfield_and_ots_key_reuse(bob_addr_state.address, multi_sig_vote6.ots_key)
            self.assertFalse(result)

            # Rollback state to block number 3
            self.assertTrue(self.chain_manager._rollback(block_3.headerhash))

            self.assertEqual(self.chain_manager.last_block.block_number, 3)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend1.txhash)
            self.assertTrue(vote_stats.executed)

            vote_stats = self.chain_manager.get_vote_stats(multi_sig_spend2.txhash)
            self.assertFalse(vote_stats.executed)
            self.assertEqual(vote_stats.total_weight, 10)

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

        # When it is obvious that the fork is longer (has a higher cum. diff), the chain manager invokes
        # _fork_recovery() and switches over to the fork
        self.chain_manager.add_block(block_4_alt)
        self.assertEqual(self.chain_manager.last_block, block_4_alt)

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_update_state_container(self, time_mock):
        """
        Features Tested
        - Behavior of update_state_container when a multisig vote txn is made for an unknown multi sig spend txn

        Expectation
        - update_state_container must return false

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 3, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)

            state_container = self.chain_manager.new_state_container(set(),
                                                                     10,
                                                                     False,
                                                                     None)

            self.assertFalse(self.chain_manager.update_state_container(multi_sig_vote1, state_container))

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_update_state_container2(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn & multisig spend txn
          both are added into same block
        - Behavior of update_state_container for multi_sig_vote1 and multi_sig_vote2 txn

        Expectation
        - update_state_container must return false and thus block should not be added as multi_sig_create
          doesnt have any balance
        - update_state_container must return false for both multi_sig_vote1 and multi_sig_vote2 txn

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, multi_sig_spend],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # from qrl.core.PoWValidator import PoWValidator
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertFalse(result)

            state_container = self.chain_manager.new_state_container(set(),
                                                                     10,
                                                                     False,
                                                                     None)

            self.assertFalse(self.chain_manager.update_state_container(multi_sig_vote1, state_container))
            self.assertFalse(self.chain_manager.update_state_container(multi_sig_vote2, state_container))

    @set_default_balance_size()
    @set_hard_fork_block_number()
    @patch('qrl.core.misc.ntp.getTime')
    def test_update_state_container3(self, time_mock):
        """
        Features Tested
        - Behavior of Block validation when multisig create txn, transfer txn & multisig spend txn
          are added into same block

        Expectation
        - update_state_container when provided with txns multi_sig_vote1 and multi_sig_vote2, it must
          return true, as the multi-sig create and spend txn both are available into the state

        :param time_mock:
        :return:
        """
        with patch.object(DifficultyTracker, 'get', return_value=ask_difficulty_tracker('2', config.dev)):
            self.chain_manager.load(self.genesis_block)

            extended_seed = "010300cebc4e25553afa0aab899f7838e59e18a48852fa9dfd5" \
                            "ae78278c371902aa9e6e9c1fa8a196d2dba0cbfd2f2d212d16c"
            random_xmss = XMSS.from_extended_seed(hstr2bin(extended_seed))
            alice_xmss = get_alice_xmss(4)
            bob_xmss = get_bob_xmss(4)
            multi_sig_create = MultiSigCreate.create(signatories=[alice_xmss.address,
                                                                  bob_xmss.address],
                                                     weights=[4, 6],
                                                     threshold=5,
                                                     fee=0,
                                                     xmss_pk=alice_xmss.pk)
            multi_sig_create.sign(alice_xmss)
            multi_sig_create.pbdata.nonce = 1
            multi_sig_address = MultiSigAddressState.generate_multi_sig_address(multi_sig_create.txhash)

            transfer_transaction = TransferTransaction.create(addrs_to=[multi_sig_address],
                                                              amounts=[40 * int(config.dev.shor_per_quanta)],
                                                              message_data=None,
                                                              fee=1 * config.dev.shor_per_quanta,
                                                              xmss_pk=bob_xmss.pk)
            transfer_transaction._data.nonce = 1
            transfer_transaction.sign(bob_xmss)
            self.assertTrue(transfer_transaction.validate_or_raise(True))

            multi_sig_spend = MultiSigSpend.create(multi_sig_address=multi_sig_address,
                                                   addrs_to=[random_xmss.address, alice_xmss.address],
                                                   amounts=[10, 5],
                                                   expiry_block_number=100,
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
            multi_sig_spend.sign(alice_xmss)
            multi_sig_spend.pbdata.nonce = 2

            multi_sig_vote1 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=alice_xmss.pk)
            multi_sig_vote1.sign(alice_xmss)
            multi_sig_vote1.pbdata.nonce = 3

            multi_sig_vote2 = MultiSigVote.create(shared_key=multi_sig_spend.txhash,
                                                  unvote=False,
                                                  fee=0,
                                                  xmss_pk=bob_xmss.pk)
            multi_sig_vote2.sign(bob_xmss)
            multi_sig_vote2.pbdata.nonce = 2
            time_mock.return_value = 1615270948  # Very high to get an easy difficulty

            seed_block = self.chain_manager.get_block_by_number(self._qn.get_seed_height(1))
            block_1 = Block.create(dev_config=config.dev,
                                   block_number=1,
                                   prev_headerhash=self.genesis_block.headerhash,
                                   prev_timestamp=self.genesis_block.timestamp,
                                   transactions=[multi_sig_create, transfer_transaction, multi_sig_spend],
                                   miner_address=alice_xmss.address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
            block_1.set_nonces(config.dev, 0, 0)

            # Uncomment only to determine the correct mining_nonce of above blocks
            # while not self.chain_manager.validate_mining_nonce(block_1.blockheader, config.dev, False):
            #     block_1.set_nonces(config.dev, block_1.mining_nonce + 1)
            #     print(block_1.mining_nonce)
            self.assertTrue(block_1.validate(self.chain_manager, {}))
            result = self.chain_manager.add_block(block_1)

            self.assertTrue(result)

            state_container = self.chain_manager.new_state_container(set(),
                                                                     10,
                                                                     False,
                                                                     None)

            self.assertTrue(self.chain_manager.update_state_container(multi_sig_vote1, state_container))
            self.assertTrue(self.chain_manager.update_state_container(multi_sig_vote2, state_container))


class TestChainManager(TestCase):
    def setUp(self):
        self.state = Mock(autospec=State)
        self.state.get_measurement.return_value = 10000000

        try:
            del GenesisBlock.instance  # Removing Singleton instance
        except Exception:  # noqa
            pass
        self.genesis_block = GenesisBlock()

        self.chain_manager = ChainManager(self.state)
        self.chain_manager.tx_pool = Mock()
        self.chain_manager._difficulty_tracker = Mock()

    @patch('qrl.core.Block.Block', autospec=True)
    def test_fork_recovery_failed(self, mock_block):
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
        self.chain_manager._rollback.return_value = [block_2.headerhash, block_1.headerhash], True

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
        with patch.object(Block, 'get_block', return_value=block_1_alt):
            # _fork_recovery() will not call _rollback(), because it has already happened.
            self.chain_manager._fork_recovery(block_3_alt, fork_state)

            # _fork_recovery() should have _rollback()ed when trying to switch to the longer chain
            self.chain_manager._rollback.assert_not_called()

    @patch('qrl.core.config')
    @patch('qrl.core.ChainManager.ChainManager.re_org_limit', new_callable=PropertyMock)
    def test_add_block_doesnt_add_blocks_beyond_reorg_limit(self, m_re_org_limit, m_height):
        # If we are at height 40000, what's the use of adding a block that's height 1? Simply ignore that block.
        m_re_org_limit.return_value = 40000
        m_height.return_value = 40000
        block_1 = create_m_block(1, self.genesis_block, alice.address)

        ans = self.chain_manager.add_block(block_1)
        self.assertFalse(ans)

    @patch('qrl.core.ChainManager.ChainManager.re_org_limit', new_callable=PropertyMock)
    def test_add_block_refuses_to_add_too_large_blocks(self, m_re_org_limit):
        # State.get_block_size_limit() calculates how large each Block should be from the last 10 confirmed blocks.
        m_re_org_limit.return_value = 0
        self.state.get_block_size_limit.return_value = 5000000
        block_1 = create_m_block(1, self.genesis_block, alice.address)
        block_1.size = 6000000

        ans = self.chain_manager.add_block(block_1)
        self.assertFalse(ans)

    @patch('qrl.core.Block.Block', autospec=True)
    def test_get_fork_point_failure_modes(self, mock_block):
        block_0 = create_m_block(0, Mock(headerhash=b'Fake Genesis', timestamp=replacement_getTime()), alice.address)
        block_1 = create_m_block(1, block_0, alice.address)
        block_2 = create_m_block(2, block_1, alice.address)

        fork_block_0 = create_m_block(0, Mock(headerhash=b'Fake Genesis', timestamp=replacement_getTime()), alice.address)
        fork_block_1 = create_m_block(1, fork_block_0, alice.address)
        fork_block_2 = create_m_block(2, fork_block_1, alice.address)

        # If _get_fork_point() ever reaches block_number 0, that means the genesis block is different!
        # Mock self.state leads us back to block_0
        mock_block.deserialize = MagicMock(side_effect=[fork_block_1, fork_block_0])
        with self.assertRaises(Exception):
            self.chain_manager._get_fork_point(fork_block_2)

        # If _get_fork_point() cannot find a particular block while walking back to the fork point, something has gone
        # very wrong
        # Mock self.state leads us back through a broken chain
        mock_block.deserialize.side_effect = [block_2, None, block_0]

        with self.assertRaises(Exception):
            self.chain_manager._get_fork_point(block_2)

    def test_try_branch_add_block_fails_if_apply_state_changes_fails(self):
        # ChainManager._try_branch_add_block() should fail if ChainManager._apply_state_changes() fails
        self.chain_manager._apply_state_changes = Mock(return_value=False)

        block = create_m_block(50, self.genesis_block, alice.address)

        block_added = self.chain_manager._try_branch_add_block(block, config.dev)
        self.assertFalse(block_added)

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

    @patch('qrl.core.Block.Block', autospec=True)
    def test_add_chain_fails_if_apply_state_changes_fails(self, mock_block_deserialize):
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
        self.chain_manager._apply_state_changes = Mock(return_value=False)
        ans = self.chain_manager.add_chain([block_1_alt.headerhash, block_2_alt.headerhash], fork_state)
        self.assertFalse(ans)

    @patch("qrl.core.Block.Block.get_block")
    def test_get_measurement(self, mock_get_block):
        def block(state, headerhash):
            nth_block = Block()
            if headerhash == b'test_block_1':
                nth_block.blockheader._data.timestamp_seconds = 50000
            elif headerhash == b'test_block_2':
                nth_block.blockheader._data.timestamp_seconds = 80000
            elif headerhash == b'test_block_3':
                nth_block.blockheader._data.timestamp_seconds = 90000
            return nth_block

        parent_metadata = BlockMetadata.create(block_difficulty=b'\x00' * 32,
                                               cumulative_difficulty=b'\x00' * 32,
                                               child_headerhashes=[])

        measurement = self.chain_manager.get_measurement(dev_config=config.dev,
                                                         block_timestamp=100000,
                                                         parent_headerhash=b'',
                                                         parent_metadata=parent_metadata)

        # Test Case, when count_headerhashes equals 0
        self.assertEqual(measurement, config.dev.block_timing_in_seconds)

        mock_get_block.side_effect = block
        parent_metadata.update_last_headerhashes([], b'test_block_1')

        measurement = self.chain_manager.get_measurement(dev_config=config.dev,
                                                         block_timestamp=100000,
                                                         parent_headerhash=b'test_block_1',
                                                         parent_metadata=parent_metadata)

        # Test Case, when count_headerhashes equals 1
        self.assertEqual(measurement,
                         (100000 - 50000 + config.dev.block_timing_in_seconds) // 2)

        parent_metadata.update_last_headerhashes([b'test_block_1'], b'test_block_2')

        measurement = self.chain_manager.get_measurement(dev_config=config.dev,
                                                         block_timestamp=100000,
                                                         parent_headerhash=b'test_block_2',
                                                         parent_metadata=parent_metadata)

        # Test Case, when count_headerhashes is greater than 1
        # but less than config.dev.N_measurement
        self.assertEqual(measurement,
                         (100000 - 80000 + config.dev.block_timing_in_seconds) // 2)

        parent_metadata.update_last_headerhashes([b'test_block_3'] * config.dev.N_measurement,
                                                 b'test_block_2')

        measurement = self.chain_manager.get_measurement(dev_config=config.dev,
                                                         block_timestamp=100000,
                                                         parent_headerhash=b'test_block_2',
                                                         parent_metadata=parent_metadata)

        # Test Case, when count_headerhashes is greater than config.dev.N_measurement
        self.assertEqual(measurement,
                         (100000 - 90000) // config.dev.N_measurement)

    def test_get_all_address_state(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                chain_manager = ChainManager(state)
                addresses_state = chain_manager.get_all_address_state()
                self.assertEqual(len(addresses_state), 0)

                alice_xmss = get_alice_xmss()
                alice_address = alice_xmss.address
                address_state = OptimizedAddressState.get_optimized_address_state(state, alice_address)
                addresses_state = {
                    alice_address: address_state
                }
                self.assertTrue(isinstance(address_state.address, bytes))
                OptimizedAddressState.put_optimized_addresses_state(state, addresses_state)

                addresses_state = chain_manager.get_all_address_state()
                self.assertEqual(len(addresses_state), 1)

                bob_xmss = get_bob_xmss()
                bob_address = bob_xmss.address
                address_state = OptimizedAddressState.get_optimized_address_state(state, bob_address)
                addresses_state = {
                    bob_address: address_state
                }
                self.assertTrue(isinstance(address_state.address, bytes))
                OptimizedAddressState.put_optimized_addresses_state(state, addresses_state)

                addresses_state = chain_manager.get_all_address_state()
                self.assertEqual(len(addresses_state), 2)

    def test_set_affected_address(self):
        block = Block.create(dev_config=config.dev,
                             block_number=10,
                             prev_headerhash=b'',
                             prev_timestamp=10,
                             transactions=[],
                             miner_address=get_some_address(1),
                             seed_height=None,
                             seed_hash=None)
        # Test Case: without any transactions of block
        self.assertEqual(self.chain_manager.set_affected_address(block),
                         {config.dev.coinbase_address, get_some_address(1)})

        alice_xmss = get_alice_xmss()
        block = Block.create(dev_config=config.dev,
                             block_number=10,
                             prev_headerhash=b'',
                             prev_timestamp=10,
                             transactions=[TransferTransaction.create(addrs_to=[get_some_address(2),
                                                                                get_some_address(3)],
                                                                      amounts=[100, 100],
                                                                      message_data=None,
                                                                      fee=0,
                                                                      xmss_pk=alice_xmss.pk)],
                             miner_address=get_some_address(1),
                             seed_height=None,
                             seed_hash=None)

        # Test Case, with one Transaction
        self.assertEqual(self.chain_manager.set_affected_address(block),
                         {config.dev.coinbase_address,
                          get_some_address(1),
                          get_some_address(2),
                          get_some_address(3),
                          alice_xmss.address})

    def test_get_block_datapoint(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                chain_manager = ChainManager(state)
                # Test Case: When block not found
                self.assertIsNone(chain_manager.get_block_datapoint(b'test'))

                alice_xmss = get_alice_xmss()
                blocks = gen_blocks(20, state, alice_xmss.address)
                for i in range(1, 20):
                    datapoint = chain_manager.get_block_datapoint(blocks[i].headerhash)
                    self.assertEqual(datapoint.difficulty, "256")
                    self.assertEqual(datapoint.timestamp, 1615270947 + i)
                    self.assertEqual(datapoint.header_hash, blocks[i].headerhash)
                    self.assertEqual(datapoint.header_hash_prev, blocks[i - 1].headerhash)

    def test_get_state_mainchain(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                chain_manager = ChainManager(state)
                alice_xmss = get_alice_xmss()
                alice_state = OptimizedAddressState.get_default(alice_xmss.address)
                alice_state.increase_nonce()
                alice_state.update_balance(None, 1000)
                addresses_state = {
                    alice_state.address: alice_state,
                }
                OptimizedAddressState.put_optimized_addresses_state(state, addresses_state, None)
                addresses_state1, success = chain_manager.get_state_mainchain({alice_state.address})

                self.assertTrue(success)
                self.assertEqual(addresses_state[alice_state.address].serialize(),
                                 addresses_state1[alice_state.address].serialize())
