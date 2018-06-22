from unittest import TestCase

from mock import patch, Mock

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.Transaction._revert_state_changes_for_PK')
@patch('qrl.core.txs.Transaction.Transaction._apply_state_changes_for_PK')
@patch('qrl.core.txs.Transaction.logger')
class TestTransferTokenTransactionStateChanges(TestCase):
    def setUp(self):
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

        self.params = {
            "token_txhash": b'I declare the TEST token',
            "addrs_to": [self.bob.address],
            "amounts": [100],
            "fee": 1,
            "xmss_pk": self.alice.pk
        }

        self.unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

    def generate_addresses_state(self, tx):
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState',
                                     tokens={self.params["token_txhash"]: 1000}, transaction_hashes=[],
                                     balance=100),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState',
                                   tokens={self.params["token_txhash"]: 0},
                                   transaction_hashes=[],
                                   balance=0),
        }
        return addresses_state

    def test_apply_state_changes(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL, Bob has none. Alice sends some tokens to Bob.
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(b'I declare the TEST token', -100)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(b'I declare the TEST token', 100)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[self.bob.address].transaction_hashes)

        m_apply_state_PK.assert_called_once()

    def test_apply_state_changes_multi_send(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL, Bob and Slave have none. Alice sends some tokens to Bob and Slave.
        """
        slave = get_slave_xmss()
        params = self.params.copy()
        params["addrs_to"] = [self.bob.address, slave.address]
        params["amounts"] = [100, 100]

        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[slave.address] = Mock(autospec=AddressState, name='slave AddressState',
                                              tokens={self.params["token_txhash"]: 0},
                                              transaction_hashes=[],
                                              balance=0)

        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        self.assertEqual(addresses_state[slave.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(b'I declare the TEST token', -200)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(b'I declare the TEST token', 100)
        addresses_state[slave.address].update_token_balance.assert_called_with(b'I declare the TEST token', 100)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[self.bob.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[slave.address].transaction_hashes)

        m_apply_state_PK.assert_called_once()

    def test_apply_state_changes_empty_addresses_state(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL, Bob has none. Alice sends some tokens to Bob.
        But this node has no AddressState corresponding to these parties.
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}
        tx.apply_state_changes(addresses_state)

        self.assertEqual({}, addresses_state)
        m_apply_state_PK.assert_called_once()

    def test_apply_state_changes_send_tokens_to_self(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL. She sends some tokens to herself. What happens next?
        """
        self.params["addrs_to"] = [self.alice.address]
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        # Unfortunately importing mock.call results in some sort of ValueError so I can't check the arguments.
        self.assertEqual(addresses_state[self.alice.address].update_token_balance.call_count, 2)

        m_apply_state_PK.assert_called_once()

    def test_revert_state_changes(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL, Bob has none. Alice sends some tokens to Bob.
        Let's undo this.
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].tokens[self.params["token_txhash"]] = 900
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]
        addresses_state[self.bob.address].balance = 0
        addresses_state[self.bob.address].tokens[self.params["token_txhash"]] = 100
        addresses_state[self.bob.address].transaction_hashes = [tx.txhash]

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(b'I declare the TEST token', 100)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(b'I declare the TEST token', -100)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)

        m_revert_state_PK.assert_called_once()

    def test_revert_state_changes_multi_send(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL, Bob and Slave have none. Alice sends some tokens to Bob and Slave.
        Undo this.
        """
        slave = get_slave_xmss()
        self.params["addrs_to"] = [self.bob.address, slave.address]
        self.params["amounts"] = [100, 100]

        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].tokens[self.params["token_txhash"]] = 900
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]
        addresses_state[self.bob.address].balance = 0
        addresses_state[self.bob.address].tokens[self.params["token_txhash"]] = 100
        addresses_state[self.bob.address].transaction_hashes = [tx.txhash]
        addresses_state[slave.address] = Mock(autospec=AddressState, name='slave AddressState',
                                              tokens={self.params["token_txhash"]: 100},
                                              transaction_hashes=[tx.txhash],
                                              balance=0)

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        self.assertEqual(addresses_state[slave.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(b'I declare the TEST token', 200)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(b'I declare the TEST token', -100)
        addresses_state[slave.address].update_token_balance.assert_called_with(b'I declare the TEST token', -100)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)
        self.assertEqual([], addresses_state[slave.address].transaction_hashes)

        m_revert_state_PK.assert_called_once()

    def test_revert_state_changes_empty_addresses_state(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        If we didn't have any AddressStates for the addresses involved in this test, do nothing
        """
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state, {})
        m_revert_state_PK.assert_called_once()

    def test_revert_state_changes_send_tokens_to_self(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        """
        Alice has 1000 tokens and 100 QRL. She sends some tokens to herself.
        Can we undo this?
        """
        self.params["addrs_to"] = [self.alice.address]
        tx = TransferTokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]
        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        # Unfortunately importing mock.call results in some sort of ValueError so I can't check the arguments.
        self.assertEqual(addresses_state[self.alice.address].update_token_balance.call_count, 2)

        m_revert_state_PK.assert_called_once()
