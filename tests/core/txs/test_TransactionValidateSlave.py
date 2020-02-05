from unittest import TestCase

from mock import patch, Mock

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.txs.MessageTransaction import MessageTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestTransactionValidateSlave(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.params = {
            "message_hash": b'Test Message',
            "addr_to": None,
            "fee": 1,
            "xmss_pk": self.alice.pk
        }
        self.m_addr_state = Mock(autospec=OptimizedAddressState, name='addr_state', balance=200)
        self.m_addr_from_pk_state = Mock(autospec=OptimizedAddressState, name='addr_from_pk_state')

    def test_validate_slave_valid(self, m_logger):
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_slave(0)
        self.assertTrue(result)

    def test_validate_slave_master_addr_same_as_signing_addr(self, m_logger):
        self.params["master_addr"] = self.alice.address
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        result = tx.validate_slave(None)
        self.assertFalse(result)

    def test_validate_slave_signing_xmss_state_has_no_slave_permissions_in_state(self, m_logger):
        bob = get_bob_xmss()
        # Let's say Alice is Bob's master.
        self.params["master_addr"] = self.alice.address
        self.params["xmss_pk"] = bob.pk

        # We need to add extra data to the mock AddressState.
        tx = MessageTransaction.create(**self.params)
        tx.sign(self.alice)
        state_container = StateContainer(addresses_state=dict(),
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        result = tx.validate_slave(state_container)
        self.assertFalse(result)
