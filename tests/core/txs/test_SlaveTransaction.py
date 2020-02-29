from unittest import TestCase

from mock import patch, PropertyMock

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from tests.misc.helper import get_alice_xmss, get_slave_xmss, get_bob_xmss, set_qrl_dir


@patch('qrl.core.txs.Transaction.logger')
class TestSlaveTransaction(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSlaveTransaction, self).__init__(*args, **kwargs)
        with set_qrl_dir('no_data'):
            self.state = State()

    def setUp(self):
        self.alice = get_alice_xmss()
        self.slave = get_slave_xmss()
        self.params = {
            "slave_pks": [self.slave.pk],
            "access_types": [0],
            "fee": 1,
            "xmss_pk": self.alice.pk
        }

    def test_create_validate(self, m_logger):
        """Default self.params should result in a valid SlaveTransaction"""
        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_or_raise()
        self.assertTrue(result)

    def test_validate_custom(self, m_logger):
        """
        SlaveTransaction._validate_custom() checks for the following things:
        1. if you specify more than 100 slave_pks at once
        2. if len(slave_pks) != len(access_types)
        3. access_types can only be 0, 1
        """
        # Unequal length slave_pks and access_types
        params = self.params.copy()
        params["slave_pks"] = [self.slave.pk]
        params["access_types"] = [0, 1]
        with self.assertRaises(ValueError):
            SlaveTransaction.create(**params)

        # access_type is a weird, undefined number
        params = self.params.copy()
        params["access_types"] = [5]
        with self.assertRaises(ValueError):
            SlaveTransaction.create(**params)

    @patch('qrl.core.txs.Transaction.Transaction.validate_slave', return_value=True)
    def test_validate_extended(self, m_validate_slave, m_logger):
        """
        SlaveTransaction._validate_extended checks for:
        1. valid master/slave
        2. negative fee,
        3. addr_from has enough funds for the fee
        4. addr_from ots_key reuse
        """
        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        alice_address_state.pbdata.balance = 100
        addresses_state = {
            alice_address_state.address: alice_address_state
        }

        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)

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
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        # Invalid master XMSS/slave XMSS relationship
        m_validate_slave.return_value = False
        result = tx.validate_all(state_container)
        self.assertFalse(result)
        m_validate_slave.return_value = True

        # fee = -1
        with patch('qrl.core.txs.SlaveTransaction.SlaveTransaction.fee', new_callable=PropertyMock) as m_fee:
            m_fee.return_value = -1
            result = tx._validate_custom()
            self.assertFalse(result)

        # balance = 0, cannot pay the Transaction fee
        alice_address_state.pbdata.balance = 0
        result = tx._validate_extended(state_container)
        self.assertFalse(result)
        alice_address_state.pbdata.balance = 100

        addresses_state = {
            self.alice.address: alice_address_state
        }
        # addr_from_pk has used this OTS key before
        state_container.paginated_bitfield.set_ots_key(addresses_state, alice_address_state.address, tx.ots_key)
        result = tx.validate_all(state_container)
        self.assertFalse(result)

        bob = get_bob_xmss()
        # Too many slave_pks
        with patch('qrl.core.config', autospec=True) as m_config:
            m_config.dev = config.dev.create(config.dev.prev_state_key, config.dev.current_state_key,
                                             b'', 10, True, True)
            m_config.dev.pbdata.transaction.multi_output_limit = 2
            state_container.current_dev_config = m_config.dev
            params = self.params.copy()
            params["slave_pks"] = [self.alice.pk, bob.pk, self.slave.pk]
            params["access_types"] = [0, 0, 0]

            tx = SlaveTransaction.create(**params)
            self.assertFalse(tx._validate_extended(state_container))

    def test_validate_tx(self, m_logger):
        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()
