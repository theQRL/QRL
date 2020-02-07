from unittest import TestCase

from mock import Mock, patch, MagicMock
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.Block import Block
from qrl.core.misc import logger
from qrl.core.ChainManager import ChainManager
from qrl.core.StateContainer import StateContainer
from qrl.core.Miner import Miner
from qrl.core.TransactionPool import TransactionPool
from qrl.core.misc.helper import parse_qaddress
from qrl.core.node import POW
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.txs.TransferTransaction import TransferTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss, replacement_getTime

logger.initialize_default()


alice = get_alice_xmss()
bob = get_bob_xmss()


@patch('qrl.core.Miner.logger')
@patch('qrl.core.misc.ntp.getTime')
class TestMiner(TestCase):
    def setUp(self):
        self.time = 1526830525
        self.m_mining_qaddress = alice.qaddress
        self.m_mining_address = parse_qaddress(self.m_mining_qaddress)

        self.chain_manager = Mock(spec=ChainManager)
        self.chain_manager.get_block_size_limit.return_value = 500
        self.chain_manager.get_config_by_block_number.return_value = config.dev
        self.parent_block = Block()
        self.parent_difficulty = StringToUInt256('0')  # tuple (0,0,0,0,0...) length 32

        self.m_pre_block_logic = Mock(spec=POW.pre_block_logic, name='hello')
        mining_thread_count = 1

        self.miner = Miner(self.chain_manager,
                           self.m_pre_block_logic,
                           self.m_mining_address,
                           mining_thread_count)

        self.txpool = Mock(spec=TransactionPool)
        self.txpool.transactions = []

    def test_prepare_next_unmined_block_template_works(self, m_getTime, m_logger):
        """
        All the setup stuff you need before you actually mine a block goes here.
        It's broken out into this function, because if you have a mining pool, this function prepares the
        getblocktemplate for the pool.
        """
        m_getTime.return_value = self.time

        self.chain_manager.get_measurement.return_value = 60
        self.txpool.transactions = []

        self.assertIsNone(self.miner._current_difficulty)
        self.assertIsNone(self.miner._current_target)
        self.assertIsNone(self.miner._measurement)
        self.miner.prepare_next_unmined_block_template(self.m_mining_address,
                                                       self.txpool,
                                                       self.parent_block,
                                                       self.parent_difficulty,
                                                       config.dev)

        self.assertEqual(self.miner._current_difficulty, StringToUInt256('2'))
        self.assertEqual(self.miner._current_target, StringToUInt256(
            '115792089237316195423570985008687907853269984665640564039457584007913129639807'))
        self.assertEqual(self.miner._measurement, 60)  # because we set it earlier in this test

    def test_prepare_next_unmined_block_template_exception(self, m_getTime, m_logger):
        """
        If this function should throw an exception, nothing should happen except a call to the logger.
        """
        m_getTime.return_value = self.time

        self.chain_manager.get_measurement.side_effect = ValueError
        self.txpool.transactions = []

        self.assertIsNone(self.miner._current_difficulty)
        self.assertIsNone(self.miner._current_target)
        self.assertIsNone(self.miner._measurement)
        self.miner.prepare_next_unmined_block_template(self.m_mining_address,
                                                       self.txpool,
                                                       self.parent_block,
                                                       self.parent_difficulty,
                                                       config.dev)

        self.assertIsNone(self.miner._current_difficulty)
        self.assertIsNone(self.miner._current_target)
        self.assertIsNone(self.miner._measurement)
        m_logger.warning.assert_called_once()
        m_logger.exception.assert_called_once()

    def test_start_mining_works(self, m_getTime, m_logger):
        m_getTime.return_value = self.time

        # Do prepare_next_unmined_block_template()'s job
        self.miner._mining_block = Block()
        # From sample run of test_prepare_next_unmined_block_template_works()
        self.miner._measurement = 60
        self.miner._current_difficulty = StringToUInt256('0')
        self.miner._current_target = \
            StringToUInt256('115792089237316195423570985008687907853269984665640564039457584007913129639807')

        # start() is from Qryptominer, let's not actually mine in a test
        with patch('qrl.core.miners.qryptonight7.CNv1Miner.CNv1Miner.start', spec=True) as m_start:
            self.miner.start_mining(self.parent_block, self.parent_difficulty, config.dev)
            m_start.assert_called_once()

    def test_get_block_to_mine_no_existing_block_being_mined_upon(self, m_getTime, m_logger):
        """
        This function takes a Qaddress, and returns a blob for the miner/mining pool to work on.
        It makes sure we have a block we're trying to mine and that the coinbase points to the Qaddress.
        In this test we  check that:
        1. If we don't have a block we're trying to mine on, it generates one on the fly.
        """
        m_getTime.return_value = 1526830525
        self.miner._current_difficulty = StringToUInt256('1')

        blob, difficulty = self.miner.get_block_to_mine(self.m_mining_qaddress.encode(), self.txpool, self.parent_block,
                                                        self.parent_difficulty)

        self.assertEqual(difficulty, 1)  # because self.miner._current_difficulty was set above
        self.assertEqual(blob,
                         '0014db80611fbf16e342a2afb8b77b1f513f9db21de3ff905c0c27ea0078c489248f37f9e2a22400000000000000000000000000000000004bfaabbf147f985be702a373183be1be77100b24')  # noqa

    def test_get_block_to_mine_not_mining_upon_last_block(self, m_getTime, m_logger):
        """
        In this test we  check that:
        2. If we aren't mining upon the last block, it regenerates the blocktemplate.
        """
        m_getTime.return_value = 1526830525
        self.miner._current_difficulty = StringToUInt256('1')
        m_mining_block = Mock(autospec=Block)
        m_mining_block.mining_blob.return_value = b'big_bad_blob'
        m_mining_block.prev_headerhash = b'nothing should be equal to this'
        self.miner._mining_block = m_mining_block

        blob, difficulty = self.miner.get_block_to_mine(self.m_mining_qaddress.encode(), self.txpool, self.parent_block,
                                                        self.parent_difficulty)

        self.assertEqual(difficulty, 1)  # because self.miner._current_difficulty was set above
        self.assertEqual(blob,
                         '0014db80611fbf16e342a2afb8b77b1f513f9db21de3ff905c0c27ea0078c489248f37f9e2a22400000000000000000000000000000000004bfaabbf147f985be702a373183be1be77100b24')  # noqa

    def test_get_block_to_mine_perfect_block_no_changes(self, m_getTime, m_logger):
        """
        In this test, we check that the function makes no changes to the block if the coinbase addr is our addr,
        and we are on the latest block.
        """
        m_coinbase = Mock(autospec=CoinBase, name='I am a Coinbase')
        m_coinbase.coinbase.addr_to = self.m_mining_address

        m_parent_block = Mock(autospec=Block, name='mock parent_block')
        m_parent_block.block_number = 10
        m_parent_block.timestamp = 0
        m_parent_block.transactions = [m_coinbase]

        m_mining_block = Mock(autospec=Block, name='mock _mining_block')
        m_mining_block.transactions = [m_coinbase]
        m_mining_block.mining_blob.return_value = b'this is the blob you should iterate the nonce upon'

        self.miner._mining_block = m_mining_block
        self.miner._current_difficulty = StringToUInt256('1')

        m_parent_block.headerhash = b'block_headerhash'
        m_mining_block.prev_headerhash = b'block_headerhash'
        blob, difficulty = self.miner.get_block_to_mine(self.m_mining_qaddress.encode(), self.txpool, m_parent_block,
                                                        self.parent_difficulty)

        self.assertEqual(blob,
                         '746869732069732074686520626c6f6220796f752073686f756c64206974657261746520746865206e6f6e63652075706f6e')
        self.assertEqual(difficulty, 1)

    def test_get_block_to_mine_we_have_a_block_in_mind(self, m_getTime, m_logger):
        """
        In this test, we check that
        1. The function checks that the blocktemplate's coinbase points to the given Qaddress
        2. The function checks that we are mining on the tip
        :param m_logger:
        :return:
        """
        m_coinbase = Mock(autospec=CoinBase, name='I am a Coinbase')
        m_coinbase.coinbase.addr_to = self.m_mining_address

        m_parent_block = Mock(autospec=Block, name='mock parent_block')
        m_parent_block.block_number = 10
        m_parent_block.timestamp = 0
        m_parent_block.transactions = [m_coinbase]

        m_mining_block = Mock(autospec=Block, name='mock _mining_block')
        m_mining_block.transactions = [m_coinbase]
        m_mining_block.mining_blob.return_value = b'this is the blob you should iterate the nonce upon'

        self.miner._mining_block = m_mining_block
        self.miner._current_difficulty = StringToUInt256('1')

        # If the coinbase doesn't point to us, make it point to us.
        foreign_qaddress = bob.qaddress
        m_parent_block.headerhash = b'block_headerhash'
        m_mining_block.prev_headerhash = b'block_headerhash'
        blob, difficulty = self.miner.get_block_to_mine(foreign_qaddress.encode(), self.txpool, m_parent_block,
                                                        self.parent_difficulty)

        # actually, the blob's value will not change because mining_block.update_mining_address() is a mock.
        # it will have the same value as in test_get_block_to_mine_perfect_block_no_changes()
        # it's enough to see that it actually runs
        m_mining_block.update_mining_address.assert_called_once()
        self.assertIsNotNone(blob)
        self.assertEqual(difficulty, 1)

    def test_get_block_to_mine_chokes_on_invalid_mining_address(self, m_getTime, m_logger):
        invalid_address = self.m_mining_qaddress + 'aaaa'
        m_parent_block = Mock(autospec=Block, name='mock parent_block')
        m_parent_block.block_number = 10
        with self.assertRaises(ValueError):
            self.miner.get_block_to_mine(invalid_address.encode(), self.txpool, m_parent_block, self.parent_difficulty)

    def test_submit_mined_block(self, m_getTime, m_logger):
        """
        This runs when a miner submits a blob with a valid nonce. It returns True only if
        BlockHeader says the nonce position is okay, and the PoWValidator says the nonce is valid.
        :param m_getTime:
        :param m_logger:
        :return:
        """
        m_mining_block = Mock(autospec=Block, name='mock _mining_block')
        m_mining_block.block_number = 10
        m_mining_block.verify_blob.return_value = False
        self.miner._mining_block = m_mining_block
        blob = 'this is a blob12345that was the nonce'.encode()

        result = self.miner.submit_mined_block(blob)
        self.assertFalse(result)

        m_mining_block.verify_blob.return_value = True
        self.chain_manager.validate_mining_nonce = MagicMock(return_value=False)
        result = self.miner.submit_mined_block(blob)
        self.assertFalse(result)

        m_mining_block.verify_blob.return_value = True
        self.chain_manager.validate_mining_nonce = MagicMock(return_value=True)
        self.m_pre_block_logic.return_value = True
        result = self.miner.submit_mined_block(blob)
        self.assertTrue(result)


@patch('qrl.core.Miner.logger')
@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestMinerWithRealTransactionPool(TestCase):
    def setUp(self):
        self.m_mining_qaddress = alice.qaddress
        self.m_mining_address = parse_qaddress(self.m_mining_qaddress)

        self.alice_address_state = Mock(autospec=OptimizedAddressState,
                                        name='mock alice OptimizedAddressState')

        self.chain_manager = Mock(spec=ChainManager)
        self.chain_manager.get_block_size_limit.return_value = 500
        self.chain_manager.get_address_state.return_value = self.alice_address_state
        self.chain_manager.get_config_by_block_number.return_value = config.dev

        self.parent_block = Block()
        self.parent_difficulty = StringToUInt256('0')  # tuple (0,0,0,0,0...) length 32

        self.m_pre_block_logic = Mock(spec=POW.pre_block_logic, name='hello')
        mining_thread_count = 1

        self.miner = Miner(self.chain_manager,
                           self.m_pre_block_logic,
                           self.m_mining_address,
                           mining_thread_count)

        self.txpool = TransactionPool(None)

        def replacement_set_affected_address(addresses_set):
            return addresses_set.add(alice.address)

        self.m_tx_args = {"addr_from": alice.address,
                          "addrs_to": [bob.address],
                          "amounts": [10],
                          "fee": 1,
                          "PK": alice.pk,
                          "master_addr": None,
                          "size": 150,
                          "validate_extended.return_value": True,
                          "set_affected_address": replacement_set_affected_address
                          }

    def mock_new_state_container(self):
        addresses_state = {alice.address: self.alice_address_state}
        self.chain_manager.new_state_container.return_value = StateContainer(addresses_state=addresses_state,
                                                                             tokens=Indexer(b'token', None),
                                                                             slaves=Indexer(b'slave', None),
                                                                             lattice_pk=Indexer(b'lattice_pk', None),
                                                                             multi_sig_spend_txs=dict(),
                                                                             votes_stats=dict(),
                                                                             block_number=5,
                                                                             total_coin_supply=0,
                                                                             current_dev_config=config.dev,
                                                                             write_access=False,
                                                                             my_db=None,
                                                                             batch=None)

    @patch('qrl.core.Miner.Block.create')
    def test_create_block_with_one_transaction(self, m_create, m_logger):
        self.mock_new_state_container()
        m_tx = Mock(autospec=TransferTransaction, name='mock TransferTransaction')
        m_tx.fee = 0
        m_tx.configure_mock(**self.m_tx_args)

        m_create.return_value = Mock(autospec=Block, name='mock Block', size=205)

        self.txpool.add_tx_to_pool(m_tx, 1, replacement_getTime())

        self.miner.create_block(last_block=self.parent_block, mining_nonce=0, tx_pool=self.txpool,
                                miner_address=self.m_mining_address)

        seed_block = self.chain_manager.get_block_by_number(
            self.miner._qn.get_seed_height(self.parent_block.block_number + 1))
        m_create.assert_called_with(dev_config=config.dev, block_number=1, prev_headerhash=b'', prev_timestamp=0,
                                    transactions=[m_tx], miner_address=alice.address,
                                    seed_height=seed_block.block_number, seed_hash=seed_block.headerhash)

    @patch('qrl.core.Miner.Block.create')
    def test_create_block_does_not_include_invalid_txs_from_txpool(self, m_create, m_logger):
        self.mock_new_state_container()
        m_tx = Mock(autospec=TransferTransaction, name='mock TransferTransaction')
        m_tx.validate_all.return_value = False
        m_tx.configure_mock(**self.m_tx_args)

        m_create.return_value = Mock(autospec=Block, name='mock Block', size=205)

        self.txpool.add_tx_to_pool(m_tx, 1, replacement_getTime())

        self.miner.create_block(last_block=self.parent_block, mining_nonce=0, tx_pool=self.txpool,
                                miner_address=self.m_mining_address)

        seed_block = self.chain_manager.get_block_by_number(
            self.miner._qn.get_seed_height(self.parent_block.block_number + 1))
        m_create.assert_called_with(dev_config=config.dev, block_number=1, prev_headerhash=b'', prev_timestamp=0,
                                    transactions=[], miner_address=alice.address,
                                    seed_height=seed_block.block_number, seed_hash=seed_block.headerhash)
