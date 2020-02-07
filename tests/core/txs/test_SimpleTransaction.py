from unittest import TestCase

import simplejson as json
from mock import patch, PropertyMock, Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.TransactionInfo import TransactionInfo
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from tests.core.txs.testdata import test_json_Simple, test_signature_Simple
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss, replacement_getTime, set_qrl_dir

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestSimpleTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSimpleTransaction, self).__init__(*args, **kwargs)
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()
        self.slave = get_slave_xmss()

        self.alice.set_ots_index(10)
        self.maxDiff = None

    def setUp(self):
        self.tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        self.tx._data.nonce = 1

    def test_create(self, m_logger):
        # Alice sending coins to Bob
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
                                        amounts=[100],
                                        message_data=None,
                                        fee=1,
                                        xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_amount(self, m_logger):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       message_data=None,
                                       fee=1,
                                       xmss_pk=self.alice.pk)

    def test_create_negative_fee(self, m_logger):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       message_data=None,
                                       fee=-1,
                                       xmss_pk=self.alice.pk)

    def test_to_json(self, m_logger):
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
                                        amounts=[100],
                                        message_data=None,
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
            message_data=None,
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
            message_data=None,
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
        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        addresses_state = {
            self.alice.address: alice_address_state
        }
        alice_address_state.pbdata.balance = 200

        self.tx.validate_slave = Mock(autospec=Transaction.validate_slave, return_value=True)

        self.tx.sign(self.alice)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        result = self.tx.validate_all(state_container)
        self.assertTrue(result)

        # Suppose there was ots key reuse. The function should then return false.
        state_container.paginated_bitfield.set_ots_key(addresses_state, self.tx.addr_from, self.tx.ots_key)
        result = self.tx.validate_all(state_container)
        self.assertFalse(result)

        # Suppose the address doesn't have enough coins.
        alice_address_state.pbdata.balance = 99
        state_container.paginated_bitfield.set_ots_key(addresses_state, self.tx.addr_from, self.tx.ots_key)
        result = self.tx.validate_all(state_container)
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
            message_data=None,
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
            message_data=None,
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
            message_data=None,
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

    def test_apply_transfer_txn(self, m_logger):
        """
        apply_state_changes() is the part that actually updates everybody's balances.
        Then it forwards the addresses_state to _apply_state_changes_for_PK(), which updates everybody's addresses's
        nonce, OTS key index, and associated TX hashes
        If there is no AddressState for a particular Address, nothing is done.
        """
        self.tx.sign(self.alice)
        ots_key = self.alice.ots_index - 1
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 200
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        self.tx.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

        # Now Alice should have 99 coins left (200 - 100 - 1) and Bob should have 100 coins.
        self.assertEqual(99, addresses_state[self.alice.address].balance)
        self.assertEqual(100, addresses_state[self.bob.address].balance)

    def test_apply_transfer_txn_tx_sends_to_self(self, m_logger):
        """
        If you send coins to yourself, you should only lose the fee for the Transaction.
        """
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 200

        tx = TransferTransaction.create(
            addrs_to=[self.alice.address],
            amounts=[100],
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.sign(self.alice)
        ots_key = self.alice.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        tx.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

        self.assertEqual(199, addresses_state[self.alice.address].balance)
        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(tx.txhash, state_container.paginated_tx_hash.key_value[storage_key])

    def test_apply_transfer_txn_multi_send(self, m_logger):
        """
        Test that apply_state_changes() also works with multiple recipients.
        """
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 200

        tx_multisend = TransferTransaction.create(
            addrs_to=[self.bob.address, self.slave.address],
            amounts=[20, 20],
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx_multisend.sign(self.alice)
        ots_key = self.alice.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        tx_multisend.apply(self.state, state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

        self.assertEqual(159, addresses_state[self.alice.address].balance)
        self.assertEqual(20, addresses_state[self.bob.address].balance)
        self.assertEqual(20, addresses_state[self.slave.address].balance)

    def test_apply_state_changes_for_PK(self, m_logger):
        """
        This updates the node's AddressState database with which OTS index a particular address should be on, and what
        tx hashes is this address associated with.
        Curiously enough, if the TX was signed by a master XMSS tree, it doesn't add this tx's txhash to the list of
        txs that address is associated with.
        :return:
        """
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address)
        }
        self.tx.sign(self.alice)
        ots_key = self.alice.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        self.tx._apply_state_changes_for_PK(state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

        self.assertEqual(1, addresses_state[self.alice.address].nonce)

    def test_apply_state_changes_for_PK_master_slave_XMSS(self, m_logger):
        """
        If the TX was signed by a slave XMSS, the slave XMSS's AddressState should be updated (not the master's).
        :return:
        """
        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            message_data=None,
            fee=1,
            xmss_pk=self.slave.pk,
            master_addr=self.alice.address
        )
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }
        tx.sign(self.slave)
        ots_key = self.slave.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)

        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.slave.address, ots_key))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, self.alice.ots_index))
        tx._apply_state_changes_for_PK(state_container)
        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.slave.address, ots_key))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, self.alice.ots_index))

        self.assertEqual(1, addresses_state[self.slave.address].nonce)
        self.assertEqual(0, addresses_state[self.alice.address].nonce)

    def test_revert_transfer_txn(self, m_logger):
        """
        Alice has sent 100 coins to Bob, using 1 as Transaction fee. Now we need to undo this.
        """
        self.tx.sign(self.alice)
        ots_key = self.alice.ots_index - 1

        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 200
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        state_container.paginated_bitfield.set_ots_key(addresses_state,
                                                       self.alice.address,
                                                       ots_key)
        state_container.paginated_bitfield.put_addresses_bitfield(None)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                           ots_key))
        self.tx.apply(self.state, state_container)
        self.tx.revert(self.state, state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address,
                                                                                            ots_key))
        self.assertEqual(0, addresses_state[self.alice.address].nonce)

        self.assertEqual(200, addresses_state[self.alice.address].balance)
        self.assertEqual(0, addresses_state[self.bob.address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

    def test_revert_transfer_txn_multi_send(self, m_logger):
        """
        Alice has sent 20 coins to Bob and Slave each, using 1 as Transaction fee. Now we need to undo this.
        """
        tx_multisend = TransferTransaction.create(
            addrs_to=[self.bob.address, self.slave.address],
            amounts=[20, 20],
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx_multisend.sign(self.alice)
        ots_key = self.alice.ots_index - 1

        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address),
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        state_container.paginated_bitfield.set_ots_key(addresses_state, self.alice.address, ots_key)
        state_container.paginated_bitfield.put_addresses_bitfield(None)
        addresses_state[self.alice.address].pbdata.balance = 200
        addresses_state[self.bob.address].pbdata.balance = 0
        addresses_state[self.slave.address].pbdata.balance = 0

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        tx_multisend.apply(self.state, state_container)
        tx_multisend.revert(self.state, state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

        self.assertEqual(200, addresses_state[self.alice.address].balance)
        self.assertEqual(0, addresses_state[self.bob.address].balance)
        self.assertEqual(0, addresses_state[self.slave.address].balance)

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.bob.address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        storage_key = state_container.paginated_tx_hash.generate_key(self.slave.address, 1)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

    def test_revert_transfer_txn_tx_sends_to_self(self, m_logger):
        """
        Alice sent coins to herself, but she still lost the Transaction fee. Undo this.
        """
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.bob.address: OptimizedAddressState.get_default(self.bob.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 200

        tx = TransferTransaction.create(
            addrs_to=[self.alice.address],
            amounts=[100],
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.sign(self.alice)
        ots_key = self.alice.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        state_container.paginated_bitfield.set_ots_key(addresses_state, self.alice.address, ots_key)
        state_container.paginated_bitfield.put_addresses_bitfield(None)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        tx.apply(self.state, state_container)
        tx.revert(self.state, state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

        self.assertEqual(200, addresses_state[self.alice.address].balance)
        self.assertEqual(0, addresses_state[self.bob.address].balance)

    def test_revert_state_changes_for_PK(self, m_logger):
        """
        This is just an undo function.
        :return:
        """
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 101
        addresses_state[self.alice.address].pbdata.nonce = 1

        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.sign(self.alice)
        ots_key = self.alice.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        state_container.paginated_bitfield.set_ots_key(addresses_state, self.alice.address, ots_key)
        state_container.paginated_bitfield.put_addresses_bitfield(None)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))
        tx._apply_state_changes_for_PK(state_container)
        tx._revert_state_changes_for_PK(state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, ots_key))

    def test_revert_state_changes_for_PK_master_slave_XMSS(self, m_logger):
        addresses_state = {
            self.alice.address: OptimizedAddressState.get_default(self.alice.address),
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }
        addresses_state[self.alice.address].pbdata.balance = 101
        addresses_state[self.slave.address].pbdata.nonce = 1

        tx = TransferTransaction.create(
            addrs_to=[self.bob.address],
            amounts=[100],
            message_data=None,
            fee=1,
            xmss_pk=self.slave.pk,
            master_addr=self.alice.address
        )
        tx.sign(self.slave)
        ots_key = self.slave.ots_index - 1
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        state_container.paginated_bitfield.set_ots_key(addresses_state, self.slave.address, ots_key)
        state_container.paginated_bitfield.put_addresses_bitfield(None)

        self.assertTrue(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.slave.address, ots_key))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, self.alice.ots_index))
        tx._apply_state_changes_for_PK(state_container)
        tx._revert_state_changes_for_PK(state_container)
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.slave.address, ots_key))
        self.assertFalse(state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(self.alice.address, self.alice.ots_index))

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
            message_data=None,
            fee=1,
            xmss_pk=self.alice.pk
        )
        tx.set_affected_address(affected_addresses)
        self.assertEqual(3, len(affected_addresses))
