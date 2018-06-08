from unittest import TestCase

from mock import patch, Mock, PropertyMock
from pyqrllib.dilithium import Dilithium
from pyqrllib.kyber import Kyber

from qrl.core.AddressState import AddressState
from qrl.core.txs.LatticePublicKey import LatticePublicKey
from tests.misc.helper import get_alice_xmss


@patch('qrl.core.txs.Transaction.logger')
class TestLatticePublicKey(TestCase):
    def setUp(self):
        self.alice = get_alice_xmss()
        k = Kyber()
        d = Dilithium()
        self.params = {
            "kyber_pk": k.getPK(),
            "dilithium_pk": d.getPK(),
            "fee": 1,
            "xmss_pk": self.alice.pk
        }

    def test_create_validate(self, m_logger):
        """Default self.params should result in a valid LatticePublicKey"""
        tx = LatticePublicKey.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_or_raise()
        self.assertTrue(result)

    @patch('qrl.core.txs.Transaction.Transaction.validate_slave', return_value=True)
    def test_validate_extended(self, m_validate_slave, m_logger):
        """
        LatticePublicKey.validate_extended checks for:
        1. valid master/slave
        2. negative fee,
        3. addr_from has enough funds for the fee
        4. addr_from ots_key reuse
        """
        m_addr_from_state = Mock(autospec=AddressState, name='addr_from State', balance=100)

        m_addr_from_pk_state = Mock(autospec=AddressState, name='addr_from_pk State')
        m_addr_from_pk_state.ots_key_reuse.return_value = False

        tx = LatticePublicKey.create(**self.params)
        tx.sign(self.alice)

        result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
        self.assertTrue(result)

        # Invalid master XMSS/slave XMSS relationship
        m_validate_slave.return_value = False
        result = tx.validate_extended(m_addr_from_state, m_addr_from_pk_state)
        self.assertFalse(result)
        m_validate_slave.return_value = True

        # fee = -1
        with patch('qrl.core.txs.LatticePublicKey.LatticePublicKey.fee', new_callable=PropertyMock) as m_fee:
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
