from unittest import TestCase

from mock import patch, Mock

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.txs.MessageTransaction import MessageTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestTransactionValidateSlave(TestCase):
    def setUp(self):
        self.alice = get_alice_xmss()
        self.params = {
            "message_hash": b'Test Message',
            "fee": 1,
            "xmss_pk": self.alice.pk
        }
        self.m_addr_state = Mock(autospec=AddressState, name='addr_state', balance=200)
        self.m_addr_from_pk_state = Mock(autospec=AddressState, name='addr_from_pk_state')

    def test_validate_slave_valid(self, m_logger):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_slave(self.m_addr_state, self.m_addr_from_pk_state)
        self.assertTrue(result)

    def test_validate_slave_master_addr_same_as_signing_addr(self, m_logger):
        self.params["master_addr"] = self.alice.address
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_slave(self.m_addr_state, self.m_addr_from_pk_state)
        self.assertFalse(result)

    def test_validate_slave_signing_xmss_state_has_no_slave_permissions_in_state(self, m_logger):
        bob = get_bob_xmss()
        # Let's say Alice is Bob's master.
        self.params["master_addr"] = self.alice.address
        self.params["xmss_pk"] = bob.pk

        # We need to add extra data to the mock AddressState.
        self.m_addr_state.slave_pks_access_type = {}
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_slave(self.m_addr_state, self.m_addr_from_pk_state)
        self.assertFalse(result)

    def test_validate_slave_has_insufficient_permissions(self, m_logger):
        """
        Master's AddressState says the Slave has permission 0.
        But Slave's AddressState says the Slave is good for permission 2.
        Therefore the Slave does not have enough permissions.
        """
        bob = get_bob_xmss()
        # Let's say Alice is Bob's master.
        self.params["master_addr"] = self.alice.address
        self.params["xmss_pk"] = bob.pk

        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)

        # The master's state says the slave can have these permissions.
        self.m_addr_state.slave_pks_access_type = {str(tx.PK): 0}
        # The signing slave's state can be 0 (full permissions) or 1 (mining only) but only 0 is used for now.
        # Let's give an invalid number.
        self.m_addr_from_pk_state.slave_pks_access_type = {str(tx.PK): 2}
        result = tx.validate_slave(self.m_addr_state, self.m_addr_from_pk_state)
        self.assertFalse(result)

        # Let's give a valid number, that matches what the master's state says (0)
        self.m_addr_from_pk_state.slave_pks_access_type = {str(tx.PK): 0}
        result = tx.validate_slave(self.m_addr_state, self.m_addr_from_pk_state)
        self.assertTrue(result)
