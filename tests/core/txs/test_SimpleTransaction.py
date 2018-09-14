from unittest import TestCase

import simplejson as json
from mock import patch, PropertyMock, Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.TransactionInfo import TransactionInfo
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from tests.core.txs.testdata import test_json_Simple, test_signature_Simple
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss, replacement_getTime

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestSimpleTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSimpleTransaction, self).__init__(*args, **kwargs)
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()
        self.slave = get_slave_xmss()

        self.alice.set_ots_index(10)
        self.maxDiff = None

    def setUp(self):
        self.tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )

    def test_create(self, m_logger):
        # Alice sending coins to Bob
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
                                        amounts=[100],
                                        fee=1,
                                        xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_amount(self, m_logger):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       fee=1,
                                       xmss_pk=self.alice.pk)

    def test_create_negative_fee(self, m_logger):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       fee=-1,
                                       xmss_pk=self.alice.pk)

    def test_to_json(self, m_logger):
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
                                        amounts=[100],
                                        fee=1,
                                        xmss_pk=self.alice.pk)
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_Simple), json.loads(txjson))

    def test_from_json(self, m_logger):
        tx = Transaction.from_json(test_json_Simple)
        tx.sign(self.alice)
        self.assertIsInstance(tx, TransferTransaction)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.addr_from))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual('554f546305d4aed6ec71c759942b721b904ab9d65eeac3c954c08c652181c4e8', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        self.assertEqual(test_signature_Simple, bin2hstr(tx.signature))

        # Test that specific content was copied over.
        self.assertEqual('0103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb385ba30f2c1c005a85ebc4419cfd',
                         bin2hstr(tx.addrs_to[0]))
        self.assertEqual(100, tx.total_amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self, m_logger):
        # If we change amount, fee, addr_from, addr_to, (maybe include xmss stuff) txhash should change.
        # Here we use the tx already defined in setUp() for convenience.
        # We must sign the tx before validation will work.
        self.tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(self.tx.validate_or_raise())

    def test_validate_tx2(self, m_logger):
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.sign(self.alice)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()

    def test_validate_tx3(self, m_logger):
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.sign(self.alice)
        tx._data.signature = tx.signature * 4183 + tx.signature[0:104]
        tx._data.transaction_hash = tx.generate_txhash()

        with self.assertRaises(ValueError):
            tx.validate_or_raise()

    @patch('qrl.core.txs.Transaction.config')
    def test_validate_tx_invalid(self, m_config, m_logger):
        # Test all the things that could make a TransferTransaction invalid
        self.tx.sign(self.alice)

        # Validation in creation, Protobuf, type conversion etc. gets in our way all the time!
        # So to get dirty data to the validate() function, we need PropertyMocks
        with patch('qrl.core.txs.TransferTransaction.TransferTransaction.amounts',
                   new_callable=PropertyMock) as m_amounts:
            # TX amount of 0 shouldn't be allowed.
            m_amounts.return_value = [0]
            with self.assertRaises(ValueError):
                self.tx.validate_or_raise()
        with patch('qrl.core.txs.TransferTransaction.TransferTransaction.fee', new_callable=PropertyMock) as m_fee:
            m_fee.return_value = -1
            with self.assertRaises(ValueError):
                self.tx.validate_or_raise()
        with patch('qrl.core.txs.TransferTransaction.TransferTransaction.addrs_to',
                   new_callable=PropertyMock) as m_addrs_to:
            with patch('qrl.core.txs.TransferTransaction.TransferTransaction.amounts',
                       new_callable=PropertyMock) as m_amounts:
                # Validation could fail because len(m_addrs_to) != len(m_amounts),
                # or if len(m_addrs_to) > transaction_multi_output_limit.
                # This second patch level is to make sure the only the latter case happens.
                m_amounts = [100, 100, 100, 100]
                m_config.dev.transaction_multi_output_limit = 3
                m_addrs_to.return_value = [2, 2, 2, 2]
                with self.assertRaises(ValueError):
                    self.tx.validate_or_raise()
        with patch('qrl.core.txs.TransferTransaction.TransferTransaction.addrs_to',
                   new_callable=PropertyMock) as m_addrs_to:
            # len(addrs_to) must equal len(amounts)
            m_addrs_to.return_value = [2, 2]
            with self.assertRaises(ValueError):
                self.tx.validate_or_raise()
        with patch('qrl.core.txs.TransferTransaction.TransferTransaction.addr_from',
                   new_callable=PropertyMock) as m_addr_from:
            m_addr_from.return_value = b'If this isnt invalid Ill eat my shoe'
            with self.assertRaises(ValueError):
                self.tx.validate_or_raise()
        with patch('qrl.core.txs.TransferTransaction.TransferTransaction.addrs_to',
                   new_callable=PropertyMock) as m_addrs_to:
            with patch('qrl.core.txs.TransferTransaction.TransferTransaction.amounts',
                       new_callable=PropertyMock) as m_amounts:
                m_amounts.return_value = [100, 100]
                m_addrs_to.return_value = [self.bob.address, b'If this isnt invalid Ill eat my shoe']
                with self.assertRaises(ValueError):
                    self.tx.validate_or_raise()

    def test_validate_extended(self, m_logger):
        """
        validate_extended() handles these parts of the validation:
        1. Master/slave
        2. balance, amount + fee from AddressState
        3. OTS key reuse from AddressState
        :return:
        """
        m_addr_state = Mock(autospec=AddressState, balance=200)
        m_addr_from_pk_state = Mock(autospec=AddressState)
        m_addr_from_pk_state.ots_key_reuse.return_value = False

        self.tx.validate_slave = Mock(autospec=Transaction.validate_slave, return_value=True)

        self.tx.sign(self.alice)

        result = self.tx.validate_extended(m_addr_state, m_addr_from_pk_state)

        self.assertTrue(result)

        # Suppose there was ots key reuse. The function should then return false.
        m_addr_from_pk_state.ots_key_reuse.return_value = True
        result = self.tx.validate_extended(m_addr_state, m_addr_from_pk_state)
        self.assertFalse(result)

        # Reset conditions from above
        m_addr_from_pk_state.ots_key_reuse.return_value = False
        # Suppose the slave XMSS address does not have permission for this type of Transaction. It should return False.
        self.tx.validate_slave.return_value = False
        result = self.tx.validate_extended(m_addr_state, m_addr_from_pk_state)
        self.assertFalse(result)

        # Reset conditions from above
        self.tx.validate_slave.return_value = True
        # Suppose the address doesn't have enough coins.
        m_addr_state.balance = 99
        result = self.tx.validate_extended(m_addr_state, m_addr_from_pk_state)
        self.assertFalse(result)

    def test_validate_transaction_pool(self, m_logger):
        """
        Two TransferTransactions. Although they're the same, they are signed with different OTS indexes.
        Therefore they should not conflict when they are both in the TransactionPool.
        :return:
        """
        tx = self.tx
        tx2 = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.sign(self.alice)
        tx2.sign(self.alice)
        tx_info = Mock(autospec=TransactionInfo, transaction=tx)
        tx2_info = Mock(autospec=TransactionInfo, transaction=tx2)
        transaction_pool = [(replacement_getTime(), tx_info), (replacement_getTime(), tx2_info)]
        result = tx.validate_transaction_pool(transaction_pool)
        self.assertTrue(result)

    def test_validate_transaction_pool_reusing_ots_index(self, m_logger):
        """
        Two different TransferTransactions. They are signed with the same OTS indexe, from the same public key.
        Therefore they should conflict.
        :return:
        """
        tx = self.tx
        tx2 = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=5,
            xmss_pk=self.alice.pk
        )

        # alice_clone's OTS index is still at 10, while self.alice will be at 11 after signing.
        alice_clone = get_alice_xmss()
        alice_clone.set_ots_index(10)
        tx.sign(self.alice)
        tx2.sign(alice_clone)

        tx_info = Mock(autospec=TransactionInfo, transaction=tx)
        tx2_info = Mock(autospec=TransactionInfo, transaction=tx2)
        transaction_pool = [(replacement_getTime(), tx_info), (replacement_getTime(), tx2_info)]

        result = tx.validate_transaction_pool(transaction_pool)
        self.assertFalse(result)

    def test_validate_transaction_pool_different_pk_same_ots_index(self, m_logger):
        """
        Two TransferTransactions. They are signed with the same OTS indexes, but from different public keys.
        Therefore they should NOT conflict.
        :return:
        """
        tx = self.tx
        tx2 = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.bob.pk
        )

        tx.sign(self.alice)
        tx2.sign(self.bob)

        tx_info = Mock(autospec=TransactionInfo, transaction=tx)
        tx2_info = Mock(autospec=TransactionInfo, transaction=tx2)
        transaction_pool = [(replacement_getTime(), tx_info), (replacement_getTime(), tx2_info)]

        result = tx.validate_transaction_pool(transaction_pool)
        self.assertTrue(result)

    def test_apply_state_changes(self, m_logger):
        """
        apply_state_changes() is the part that actually updates everybody's balances.
        Then it forwards the addresses_state to _apply_state_changes_for_PK(), which updates everybody's addresses's
        nonce, OTS key index, and associated TX hashes
        If there is no AddressState for a particular Address, nothing is done.
        """
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[],
                                     balance=200),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', transaction_hashes=[], balance=0),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState', transaction_hashes=[], balance=0)
        }
        self.tx._apply_state_changes_for_PK = Mock(autospec=TransferTransaction._apply_state_changes_for_PK)

        self.tx.apply_state_changes(addresses_state)

        # Now Alice should have 99 coins left (200 - 100 - 1) and Bob should have 100 coins.
        self.assertEqual(99, addresses_state[self.alice.address].balance)
        self.assertEqual(100, addresses_state[self.bob.address].balance)
        self.tx._apply_state_changes_for_PK.assert_called_once()

        # If there are no AddressStates related to the Addresses in this transaction, do nothing.
        self.tx._apply_state_changes_for_PK.reset_mock()
        addresses_state_dummy = {
            b'a': 'ABC',
            b'b': 'DEF'
        }
        self.tx.apply_state_changes(addresses_state_dummy)
        self.assertEqual(addresses_state_dummy, {b'a': 'ABC', b'b': 'DEF'})
        self.tx._apply_state_changes_for_PK.assert_called_once()

    def test_apply_state_changes_tx_sends_to_self(self, m_logger):
        """
        If you send coins to yourself, you should only lose the fee for the Transaction.
        """
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[],
                                     balance=200),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', transaction_hashes=[], balance=0),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState', transaction_hashes=[], balance=0)
        }
        tx = TransferTransaction.create(
            addrs_to=[self.alice.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx._apply_state_changes_for_PK = Mock(autospec=TransferTransaction._revert_state_changes_for_PK)

        tx.apply_state_changes(addresses_state)

        self.assertEqual(199, addresses_state[self.alice.address].balance)
        self.assertIn(tx.txhash, addresses_state[self.alice.address].transaction_hashes)

    def test_apply_state_changes_multi_send(self, m_logger):
        """
        Test that apply_state_changes() also works with multiple recipients.
        """
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[],
                                     balance=200),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', transaction_hashes=[], balance=0),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState', transaction_hashes=[], balance=0)
        }

        tx_multisend = TransferTransaction.create(
            addrs_to=[self.bob.address, self.slave.address],
            amounts=[20, 20],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx_multisend._apply_state_changes_for_PK = Mock(autospec=TransferTransaction._apply_state_changes_for_PK)

        tx_multisend.apply_state_changes(addresses_state)

        # Now Alice should have 159 coins left (200 - 20 - 20 - 1) and Bob should have 100 coins.
        self.assertEqual(159, addresses_state[self.alice.address].balance)
        self.assertEqual(20, addresses_state[self.bob.address].balance)
        self.assertEqual(20, addresses_state[self.slave.address].balance)
        tx_multisend._apply_state_changes_for_PK.assert_called_once()

    def test_apply_state_changes_for_PK(self, m_logger):
        """
        This updates the node's AddressState database with which OTS index a particular address should be on, and what
        tx hashes is this address associated with.
        Curiously enough, if the TX was signed by a master XMSS tree, it doesn't add this tx's txhash to the list of
        txs that address is associated with.
        :return:
        """
        addr_state = {
            self.alice.address: Mock(autospec=AddressState)
        }
        old_ots_index = self.alice.ots_index
        self.tx.sign(self.alice)
        self.tx._apply_state_changes_for_PK(addr_state)

        addr_state[self.alice.address].increase_nonce.assert_called_once()
        addr_state[self.alice.address].set_ots_key.assert_called_once_with(old_ots_index)

    def test_apply_state_changes_for_PK_master_slave_XMSS(self, m_logger):
        """
        If the TX was signed by a slave XMSS, the slave XMSS's AddressState should be updated (not the master's).
        :return:
        """
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.slave.pk,
            master_addr=self.alice.address
        )
        addr_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState'),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState')
        }
        old_ots_index = self.slave.ots_index
        tx.sign(self.slave)
        tx._apply_state_changes_for_PK(addr_state)

        addr_state[self.slave.address].increase_nonce.assert_called_once()
        addr_state[self.slave.address].set_ots_key.assert_called_once_with(old_ots_index)
        addr_state[self.slave.address].transaction_hashes.append.assert_called_once()

    def test_revert_state_changes(self, m_logger):
        """
        Alice has sent 100 coins to Bob, using 1 as Transaction fee. Now we need to undo this.
        """
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState',
                                     transaction_hashes=[self.tx.txhash],
                                     balance=99),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', transaction_hashes=[self.tx.txhash],
                                   balance=100),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState', transaction_hashes=[], balance=0)
        }

        unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')
        self.tx._revert_state_changes_for_PK = Mock(autospec=TransferTransaction._revert_state_changes_for_PK)

        self.tx.revert_state_changes(addresses_state, unused_chain_manager_mock)

        self.assertEqual(200, addresses_state[self.alice.address].balance)
        self.assertEqual(0, addresses_state[self.bob.address].balance)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)

        self.tx._revert_state_changes_for_PK.assert_called_once()

        # If there are no AddressStates related to the Addresses in this transaction, do nothing.
        self.tx._revert_state_changes_for_PK.reset_mock()
        addresses_state_dummy = {
            b'a': 'ABC',
            b'b': 'DEF'
        }
        self.tx.revert_state_changes(addresses_state_dummy, unused_chain_manager_mock)
        self.assertEqual(addresses_state_dummy, {b'a': 'ABC', b'b': 'DEF'})
        self.tx._revert_state_changes_for_PK.assert_called_once()

    def test_revert_state_changes_multi_send(self, m_logger):
        """
        Alice has sent 20 coins to Bob and Slave each, using 1 as Transaction fee. Now we need to undo this.
        """
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState',
                                     transaction_hashes=[self.tx.txhash],
                                     balance=159),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', transaction_hashes=[self.tx.txhash],
                                   balance=20),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState',
                                     transaction_hashes=[self.tx.txhash], balance=20)
        }
        unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

        tx_multisend = TransferTransaction.create(
            addrs_to=[self.bob.address, self.slave.address],
            amounts=[20, 20],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx_multisend._revert_state_changes_for_PK = Mock(autospec=TransferTransaction._revert_state_changes_for_PK)

        tx_multisend.revert_state_changes(addresses_state, unused_chain_manager_mock)

        self.assertEqual(200, addresses_state[self.alice.address].balance)
        self.assertEqual(0, addresses_state[self.bob.address].balance)
        self.assertEqual(0, addresses_state[self.slave.address].balance)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.slave.address].transaction_hashes)

        tx_multisend._revert_state_changes_for_PK.assert_called_once()

    def test_revert_state_changes_tx_sends_to_self(self, m_logger):
        """
        Alice sent coins to herself, but she still lost the Transaction fee. Undo this.
        """
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState',
                                     transaction_hashes=[self.tx.txhash],
                                     balance=199),
            self.bob.address: Mock(autospec=AddressState, name='bob AddressState', transaction_hashes=[],
                                   balance=0),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState', transaction_hashes=[], balance=0)
        }

        unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

        tx = TransferTransaction.create(
            addrs_to=[self.alice.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )

        tx._revert_state_changes_for_PK = Mock(autospec=TransferTransaction._revert_state_changes_for_PK)

        tx.revert_state_changes(addresses_state, unused_chain_manager_mock)

        self.assertEqual(200, addresses_state[self.alice.address].balance)
        self.assertEqual(0, addresses_state[self.bob.address].balance)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        self.assertEqual([], addresses_state[self.bob.address].transaction_hashes)

        tx._revert_state_changes_for_PK.assert_called_once()

    def test_revert_state_changes_for_PK(self, m_logger):
        """
        This is just an undo function.
        :return:
        """
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.alice.pk
        )
        addr_state = {
            self.alice.address: Mock(autospec=AddressState)
        }
        tx.sign(self.alice)
        tx._revert_state_changes_for_PK(addr_state, Mock(name='unused State Mock'))

        addr_state[self.alice.address].decrease_nonce.assert_called_once()
        addr_state[self.alice.address].unset_ots_key.assert_called_once()

    def test_revert_state_changes_for_PK_master_slave_XMSS(self, m_logger):
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            fee=1,
            xmss_pk=self.slave.pk,
            master_addr=self.alice.address
        )
        addr_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState'),
            self.slave.address: Mock(autospec=AddressState, name='slave AddressState')
        }
        tx.sign(self.slave)
        tx._revert_state_changes_for_PK(addr_state, Mock(name='unused State Mock'))

        addr_state[self.slave.address].decrease_nonce.assert_called_once()
        addr_state[self.slave.address].unset_ots_key.assert_called_once()
        addr_state[self.slave.address].transaction_hashes.remove.assert_called_once()

    def test_affected_address(self, m_logger):
        # The default transaction params involve only two addresses.
        affected_addresses = set()
        self.tx.set_affected_address(affected_addresses)
        self.assertEqual(2, len(affected_addresses))

        # This transaction should involve 3 addresses.
        affected_addresses = set()
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address, self.slave.address],
            amounts=[100, 100],
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.set_affected_address(affected_addresses)
        self.assertEqual(3, len(affected_addresses))
