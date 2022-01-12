from unittest import TestCase

import simplejson as json
from mock import patch, Mock, PropertyMock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.misc import logger
from qrl.core.formulas import block_reward
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.BlockHeader import BlockHeader
from qrl.core.txs.CoinBase import CoinBase
from qrl.crypto.misc import sha256
from tests.core.txs.testdata import test_json_CoinBase
from tests.misc.helper import get_alice_xmss, set_qrl_dir

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestCoinBase(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCoinBase, self).__init__(*args, **kwargs)
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.alice.set_ots_index(11)

        self.mock_blockheader = Mock(spec=BlockHeader)
        self.mock_blockheader.stake_selector = self.alice.address
        self.mock_blockheader.block_reward = 50
        self.mock_blockheader.fee_reward = 40
        self.mock_blockheader.prev_headerhash = sha256(b'prev_headerhash')
        self.mock_blockheader.block_number = 1
        self.mock_blockheader.headerhash = sha256(b'headerhash')

        self.amount = self.mock_blockheader.block_reward + self.mock_blockheader.fee_reward
        self.maxDiff = None

    def test_create(self, m_logger):
        tx = CoinBase.create(config.dev, self.amount, self.alice.address, self.mock_blockheader.block_number)
        self.assertIsInstance(tx, CoinBase)

    def test_to_json(self, m_logger):
        amount = self.mock_blockheader.block_reward + self.mock_blockheader.fee_reward
        tx = CoinBase.create(config.dev, amount, self.alice.address, self.mock_blockheader.block_number)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_CoinBase), json.loads(txjson))

    def test_from_txdict(self, m_logger):
        amount = self.mock_blockheader.block_reward + self.mock_blockheader.fee_reward
        tx = CoinBase.create(config.dev, amount, self.alice.address, self.mock_blockheader.block_number)
        self.assertIsInstance(tx, CoinBase)

        # Test that common Transaction components were copied over.
        self.assertEqual(self.mock_blockheader.block_number + 1, tx.nonce)
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.addr_to))

        self.assertEqual('222460cc57ab8683b46f1831fe6cf1832c7e3134baf74d33bfaf91741e19cba2', bin2hstr(tx.txhash))
        self.assertEqual(tx.amount, 90)

    def test_validate_custom(self, m_logger):
        """
        CoinBase _validate_custom() only checks if fee == 0
        """
        tx = CoinBase.create(config.dev, self.amount, self.alice.address, self.mock_blockheader.block_number)
        tx._data.fee = 1
        result = tx._validate_custom()
        self.assertFalse(result)

        tx._data.fee = 0
        result = tx._validate_custom()
        self.assertTrue(result)

    def test_validate_extended(self, m_logger):
        """
        CoinBase validate_extended() checks for
        1. valid coinbase address (the coinbase address must be config.dev.coinbase_address)
        2. valid addr_to
        then calls _validate_custom()
        """
        tx = CoinBase.create(config.dev, self.amount, self.alice.address, self.mock_blockheader.block_number)
        tx._data.master_addr = self.alice.address

        addresses_state = {
            config.dev.coinbase_address: OptimizedAddressState.get_default(config.dev.coinbase_address),
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
        }
        addresses_state[config.dev.coinbase_address].pbdata.balance = 1000000

        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=self.mock_blockheader.block_number,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        tx._data.master_addr = config.dev.coinbase_address
        with patch('qrl.core.txs.CoinBase.CoinBase.addr_to', new_callable=PropertyMock) as m_addr_to:
            m_addr_to.return_value = b'Fake Address'
            result = tx._validate_extended(state_container)
            self.assertFalse(result)

        result = tx._validate_extended(state_container)
        self.assertTrue(result)

    def test_apply_coinbase_txn(self, m_logger):
        """
        Alice earned some coins.
        """
        addresses_state = {
            config.dev.coinbase_address: OptimizedAddressState.get_default(config.dev.coinbase_address),
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
        }
        addresses_state[config.dev.coinbase_address].pbdata.balance = 1000000000000000
        tx = CoinBase.create(config.dev, self.amount, self.alice.address, self.mock_blockheader.block_number)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=self.mock_blockheader.block_number,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        # self.state.apply(tx, addresses_state)
        tx.apply(self.state, state_container)
        reward = int(block_reward(self.mock_blockheader.block_number, config.dev))
        self.assertEqual(1000000000000000 - reward, addresses_state[config.dev.coinbase_address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(config.dev.coinbase_address, 1)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])
        self.assertEqual(tx.amount, addresses_state[self.alice.address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

    def test_revert_coinbase_txn(self, m_logger):
        """
        Alice earned some coins. Undo this.
        """
        tx = CoinBase.create(config.dev, self.amount, self.alice.address, self.mock_blockheader.block_number)
        addresses_state = {
            config.dev.coinbase_address: OptimizedAddressState.get_default(config.dev.coinbase_address),
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
        }
        addresses_state[config.dev.coinbase_address].pbdata.balance = 1000000000000000

        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=self.mock_blockheader.block_number,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        tx.apply(self.state, state_container)
        tx.revert(self.state, state_container)

        self.assertEqual(1000000000000000, addresses_state[config.dev.coinbase_address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(config.dev.coinbase_address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])
        self.assertEqual(0, addresses_state[self.alice.address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(config.dev.coinbase_address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

    def test_affected_address(self, m_logger):
        # This transaction can only involve 2 addresses.
        affected_addresses = set()
        tx = CoinBase.create(config.dev, self.amount, self.alice.address, self.mock_blockheader.block_number)
        tx.set_affected_address(affected_addresses)
        self.assertEqual(2, len(affected_addresses))
