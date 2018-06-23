from unittest import TestCase

from mock import patch, Mock

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.MessageTransaction import MessageTransaction
from tests.misc.helper import get_alice_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.Transaction._revert_state_changes_for_PK')
@patch('qrl.core.txs.Transaction.Transaction._apply_state_changes_for_PK')
@patch('qrl.core.txs.Transaction.logger')
class TestMessageTransactionStateChanges(TestCase):
    def setUp(self):
        self.alice = get_alice_xmss()

        self.params = {
            "message_hash": b'Test Message',
            "fee": 1,
            "xmss_pk": self.alice.pk
        }
        self.unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

    def generate_addresses_state(self, tx):
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[],
                                     balance=100),
        }
        return addresses_state

    def test_apply_state_changes(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)

        m_apply_state_PK.assert_called_once()

    def test_apply_state_changes_empty_addresses_state(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}
        tx.apply_state_changes(addresses_state)

        self.assertEqual({}, addresses_state)
        m_apply_state_PK.assert_called_once()

    def test_revert_state_changes(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)

        m_revert_state_PK.assert_called_once()

    def test_revert_state_changes_empty_addresses_state(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}
        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual({}, addresses_state)
        m_revert_state_PK.assert_called_once()

    def test_validate_tx(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()
