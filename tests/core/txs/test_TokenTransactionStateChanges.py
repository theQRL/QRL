from unittest import TestCase

from mock import patch, Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.generated import qrl_pb2
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestTokenTransactionStateChanges(TestCase):
    def setUp(self):
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

        self.params = {
            "symbol": b'QRL',
            "name": b'Quantum Resistant Ledger',
            "owner": self.alice.address,
            "decimals": 15,
            "initial_balances": [],
            "fee": 1,
            "xmss_pk": self.alice.pk
        }

        self.unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

    def generate_addresses_state(self, tx):
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState',
                                     tokens={bin2hstr(tx.txhash): 0}, transaction_hashes=[],
                                     balance=100),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', tokens={bin2hstr(tx.txhash): 0},
                                   transaction_hashes=[],
                                   balance=0),
        }
        return addresses_state

    def test_apply_state_changes(self, m_logger):
        """
        Alice creates a token. Obviously, she gives herself some of this token.
        But she also gives Bob some tokens too.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)

        # According to the State, Alice has 100 coins, and Bob has 0 coins.
        # After applying the Transaction, Alice and Bob should have 1000 tokens, and Alice's balance should be 99.
        # AddressState.transaction_hashes now also reference the TokenTransaction that created the Tokens.
        tx.apply_state_changes(addresses_state)
        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(tx.txhash, 1000)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(tx.txhash, 1000)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[self.bob.address].transaction_hashes)
        addresses_state[self.alice.address].increase_nonce.assert_called_once()
        addresses_state[self.alice.address].set_ots_key.assert_called_once()
        addresses_state[self.bob.address].increase_nonce.assert_not_called()
        addresses_state[self.bob.address].set_ots_key.assert_not_called()

    def test_apply_state_changes_empty_addresses_state(self, m_logger):
        """
        After applying the Transaction, Alice and Bob should have 1000 tokens, and Alice's balance should be 99.
        AddressState.transaction_hashes now also reference the TokenTransaction that created the Tokens.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances
        addresses_state_empty = {}

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)

        tx.apply_state_changes(addresses_state_empty)
        self.assertEqual(addresses_state_empty, {})

    def test_apply_state_changes_owner_not_in_address_state(self, m_logger):
        """
        In this case, Alice didn't give herself any tokens. How generous! She gave them all to Bob.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)

        # Signing the TX also generates the txhash, which we need to generate the AddressState properly.
        addresses_state = self.generate_addresses_state(tx)
        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[self.bob.address].transaction_hashes)
        addresses_state[self.alice.address].increase_nonce.assert_called_once()
        addresses_state[self.alice.address].set_ots_key.assert_called_once()
        addresses_state[self.bob.address].increase_nonce.assert_not_called()
        addresses_state[self.bob.address].set_ots_key.assert_not_called()

    def test_apply_state_changes_signed_by_slave_xmss(self, m_logger):
        """
        Alice creates a token, gives herself and Bob some tokens.
        But she uses a XMSS slave to sign it.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        slave = get_slave_xmss()
        self.params["initial_balances"] = initial_balances
        self.params["xmss_pk"] = slave.pk
        self.params["master_addr"] = self.alice.address
        tx = TokenTransaction.create(**self.params)
        tx.sign(slave)

        # Now that we have the Slave XMSS address, we should add it to AddressState so that apply_state_changes()
        # can do something with it
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[slave.address] = Mock(autospec=AddressState,
                                              name='slave AddressState',
                                              tokens={bin2hstr(tx.txhash): 0},
                                              transaction_hashes=[],
                                              balance=0)

        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(tx.txhash, 1000)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(tx.txhash, 1000)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[slave.address].transaction_hashes)
        self.assertEqual([tx.txhash], addresses_state[self.bob.address].transaction_hashes)
        addresses_state[slave.address].increase_nonce.assert_called_once()
        addresses_state[slave.address].set_ots_key.assert_called_once()
        addresses_state[self.alice.address].increase_nonce.assert_not_called()
        addresses_state[self.alice.address].set_ots_key.assert_not_called()

    def test_revert_state_changes(self, m_logger):
        """
        Same setup as in test_apply_state_changes(). This time though, the changes have already been applied,
        and we would like to roll them back.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)
        # Apply the changes!
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].tokens[bin2hstr(tx.txhash)] = 1000
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]
        addresses_state[self.bob.address].tokens[bin2hstr(tx.txhash)] = 1000
        addresses_state[self.bob.address].transaction_hashes = [tx.txhash]

        # After applying the Transaction, it should be as if Alice had never created the tokens in the first place.
        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(tx.txhash, -1000)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(tx.txhash, -1000)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)
        addresses_state[self.alice.address].decrease_nonce.assert_called_once()
        addresses_state[self.alice.address].unset_ots_key.assert_called_once()
        addresses_state[self.bob.address].decrease_nonce.assert_not_called()
        addresses_state[self.bob.address].unset_ots_key.assert_not_called()

    def test_revert_state_changes_empty_addresses_state(self, m_logger):
        """If we didn't have any AddressStates for the addresses involved in this test, do nothing"""
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state, {})

    def test_revert_state_changes_owner_not_in_address_state(self, m_logger):
        """
        In this case, Alice didn't give herself any tokens. How generous! She gave them all to Bob.
        But we want to revert this.
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        self.params["initial_balances"] = initial_balances

        tx = TokenTransaction.create(**self.params)
        tx.sign(self.alice)

        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]
        addresses_state[self.bob.address].tokens[bin2hstr(tx.txhash)] = 1000
        addresses_state[self.bob.address].transaction_hashes = [tx.txhash]

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual(addresses_state[self.bob.address].balance, 0)
        addresses_state[self.alice.address].update_token_balance.assert_not_called()
        addresses_state[self.bob.address].update_token_balance.assert_called_with(tx.txhash, -1000)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)
        addresses_state[self.alice.address].decrease_nonce.assert_called_once()
        addresses_state[self.alice.address].unset_ots_key.assert_called_once()
        addresses_state[self.bob.address].decrease_nonce.assert_not_called()
        addresses_state[self.bob.address].unset_ots_key.assert_not_called()

    def test_revert_state_changes_signed_by_slave_xmss(self, m_logger):
        """
        Alice creates a token, gives herself and Bob some tokens.
        But she uses a XMSS slave to sign it.
        Can we undo it?
        """
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        slave = get_slave_xmss()
        self.params["initial_balances"] = initial_balances
        self.params["xmss_pk"] = slave.pk
        self.params["master_addr"] = self.alice.address
        tx = TokenTransaction.create(**self.params)
        tx.sign(slave)

        # Now that we have the Slave XMSS address, we should add it to AddressState so that apply_state_changes()
        # can do something with it
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[slave.address] = Mock(autospec=AddressState,
                                              name='slave AddressState',
                                              tokens={bin2hstr(tx.txhash): 0},
                                              transaction_hashes=[],
                                              balance=0)
        # Also, update the AddressStates manually!
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]
        addresses_state[self.alice.address].tokens[bin2hstr(tx.txhash)] = 1000
        addresses_state[self.bob.address].balance = 0
        addresses_state[self.bob.address].transaction_hashes = [tx.txhash]
        addresses_state[self.bob.address].tokens[bin2hstr(tx.txhash)] = 1000
        addresses_state[slave.address].transaction_hashes = [tx.txhash]

        tx.revert_state_changes(addresses_state, self.unused_chain_manager_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        addresses_state[self.alice.address].update_token_balance.assert_called_with(tx.txhash, -1000)
        addresses_state[self.bob.address].update_token_balance.assert_called_with(tx.txhash, -1000)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[slave.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)
        addresses_state[slave.address].decrease_nonce.assert_called_once()
        addresses_state[slave.address].unset_ots_key.assert_called_once()
        addresses_state[self.alice.address].decrease_nonce.assert_not_called()
        addresses_state[self.alice.address].unset_ots_key.assert_not_called()

    def test_validate_tx(self, m_logger):
        initial_balances = [qrl_pb2.AddressAmount(address=self.alice.address, amount=1000),
                            qrl_pb2.AddressAmount(address=self.bob.address, amount=1000)]
        slave = get_slave_xmss()
        self.params["initial_balances"] = initial_balances
        self.params["xmss_pk"] = slave.pk
        self.params["master_addr"] = self.alice.address
        tx = TokenTransaction.create(**self.params)
        tx.sign(slave)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()
