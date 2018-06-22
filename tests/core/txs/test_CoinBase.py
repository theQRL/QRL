from unittest import TestCase

import simplejson as json
from mock import patch, Mock, PropertyMock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.BlockHeader import BlockHeader
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.CoinBase import CoinBase
from qrl.crypto.misc import sha256
from tests.core.txs.testdata import test_json_CoinBase
from tests.misc.helper import get_alice_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestCoinBase(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCoinBase, self).__init__(*args, **kwargs)

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
        tx = CoinBase.create(self.amount, self.alice.address, self.mock_blockheader.block_number)
        self.assertIsInstance(tx, CoinBase)

    def test_to_json(self, m_logger):
        amount = self.mock_blockheader.block_reward + self.mock_blockheader.fee_reward
        tx = CoinBase.create(amount, self.alice.address, self.mock_blockheader.block_number)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_CoinBase), json.loads(txjson))

    def test_from_txdict(self, m_logger):
        amount = self.mock_blockheader.block_reward + self.mock_blockheader.fee_reward
        tx = CoinBase.create(amount, self.alice.address, self.mock_blockheader.block_number)
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
        tx = CoinBase.create(self.amount, self.alice.address, self.mock_blockheader.block_number)
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
        tx = CoinBase.create(self.amount, self.alice.address, self.mock_blockheader.block_number)
        tx._data.master_addr = self.alice.address

        result = tx.validate_extended(self.mock_blockheader.block_number)
        self.assertFalse(result)

        tx._data.master_addr = config.dev.coinbase_address
        with patch('qrl.core.txs.CoinBase.CoinBase.addr_to', new_callable=PropertyMock) as m_addr_to:
            m_addr_to.return_value = b'Fake Address'
            result = tx.validate_extended(self.mock_blockheader.block_number)
            self.assertFalse(result)

        result = tx.validate_extended(self.mock_blockheader.block_number)
        self.assertTrue(result)

    def test_apply_state_changes(self, m_logger):
        """
        Alice earned some coins.
        """
        addresses_state = {
            config.dev.coinbase_address: Mock(autospec=AddressState, name='CoinBase AddressState',
                                              transaction_hashes=[], balance=1000000),
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[],
                                     balance=0),
        }
        tx = CoinBase.create(self.amount, self.alice.address, self.mock_blockheader.block_number)

        tx.apply_state_changes(addresses_state)

        self.assertEqual(1000000 - tx.amount, addresses_state[config.dev.coinbase_address].balance)
        self.assertEqual([tx.txhash], addresses_state[config.dev.coinbase_address].transaction_hashes)
        self.assertEqual(tx.amount, addresses_state[self.alice.address].balance)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)

        # A blank addresses_state doesn't get modified at all (but in practice, every node should have an AddressState
        # for the CoinBase addr
        addresses_state_empty = {}
        tx.apply_state_changes(addresses_state_empty)
        self.assertEqual({}, addresses_state_empty)

    def test_revert_state_changes(self, m_logger):
        """
        Alice earned some coins. Undo this.
        """
        tx = CoinBase.create(self.amount, self.alice.address, self.mock_blockheader.block_number)
        addresses_state = {
            config.dev.coinbase_address: Mock(autospec=AddressState, name='CoinBase AddressState',
                                              transaction_hashes=[tx.txhash], balance=1000000 - self.amount),
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[tx.txhash],
                                     balance=self.amount),
        }
        unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

        tx.revert_state_changes(addresses_state, unused_chain_manager_mock)

        self.assertEqual(1000000, addresses_state[config.dev.coinbase_address].balance)
        self.assertEqual([], addresses_state[config.dev.coinbase_address].transaction_hashes)
        self.assertEqual(0, addresses_state[self.alice.address].balance)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)

        # A blank addresses_state doesn't get modified at all (but in practice, every node should have an AddressState
        # for the CoinBase addr
        addresses_state_empty = {}
        tx.revert_state_changes(addresses_state_empty, unused_chain_manager_mock)
        self.assertEqual({}, addresses_state_empty)

    def test_affected_address(self, m_logger):
        # This transaction can only involve 2 addresses.
        affected_addresses = set()
        tx = CoinBase.create(self.amount, self.alice.address, self.mock_blockheader.block_number)
        tx.set_affected_address(affected_addresses)
        self.assertEqual(2, len(affected_addresses))
