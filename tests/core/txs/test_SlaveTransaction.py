from unittest import TestCase

from mock import patch, Mock, PropertyMock

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from tests.misc.helper import get_alice_xmss, get_slave_xmss, get_bob_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestSlaveTransaction(TestCase):
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
        # We're going to need all the XMSS trees we can get here
        bob = get_bob_xmss()

        # Too many slave_pks
        with patch('qrl.core.txs.SlaveTransaction.config', autospec=True) as m_config:
            m_config.dev.transaction_multi_output_limit = 2
            params = self.params.copy()
            params["slave_pks"] = [self.alice.pk, bob.pk, self.slave.pk]
            params["access_types"] = [0, 0, 0]

            with self.assertRaises(ValueError):
                SlaveTransaction.create(**params)

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
        SlaveTransaction.validate_extended checks for:
        1. valid master/slave
        2. negative fee,
        3. addr_from has enough funds for the fee
        4. addr_from ots_key reuse
        """
        m_addr_from_state = Mock(autospec=AddressState, name='addr_from State', balance=100)

        m_addr_from_pk_state = Mock(autospec=AddressState, name='addr_from_pk State')
        m_addr_from_pk_state.ots_key_reuse.return_value = False

        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)

        result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
        self.assertTrue(result)

        # Invalid master XMSS/slave XMSS relationship
        m_validate_slave.return_value = False
        result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
        self.assertFalse(result)
        m_validate_slave.return_value = True

        # fee = -1
        with patch('qrl.core.txs.SlaveTransaction.SlaveTransaction.fee', new_callable=PropertyMock) as m_fee:
            m_fee.return_value = -1
            result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
            self.assertFalse(result)

        # balance = 0, cannot pay the Transaction fee
        m_addr_from_state.balance = 0
        result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
        self.assertFalse(result)
        m_addr_from_state.balance = 100

        # addr_from_pk has used this OTS key before
        m_addr_from_pk_state.ots_key_reuse.return_value = True
        result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
        self.assertFalse(result)

    def test_validate_tx(self, m_logger):
        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()
