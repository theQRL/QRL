from unittest import TestCase

from mock import patch, Mock
from pyqrllib.dilithium import Dilithium
from pyqrllib.kyber import Kyber

from qrl.core.AddressState import AddressState
from qrl.core.txs.LatticePublicKey import LatticePublicKey
from tests.misc.helper import get_alice_xmss


@patch('qrl.core.txs.Transaction.Transaction._revert_state_changes_for_PK')
@patch('qrl.core.txs.Transaction.Transaction._apply_state_changes_for_PK')
@patch('qrl.core.txs.Transaction.logger')
class TestLatticePublicKeyStateChanges(TestCase):
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

        self.unused_state_mock = Mock(autospec=AddressState, name='unused State Mock')

    def generate_addresses_state(self, tx):
        addresses_state = {
            self.alice.address: Mock(autospec=AddressState, name='alice AddressState', transaction_hashes=[],
                                     balance=100)
        }
        return addresses_state

    def test_apply_state_changes(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = LatticePublicKey.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        tx.apply_state_changes(addresses_state)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)
        self.assertEqual([tx.txhash], addresses_state[self.alice.address].transaction_hashes)
        addresses_state[self.alice.address].add_lattice_pk.assert_called_once()

        m_apply_state_PK.assert_called_once()

    def test_apply_state_changes_empty_addresses_state(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = LatticePublicKey.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}
        tx.apply_state_changes(addresses_state)

        self.assertEqual({}, addresses_state)
        m_apply_state_PK.assert_called_once()

    def test_revert_state_changes(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = LatticePublicKey.create(**self.params)
        tx.sign(self.alice)
        addresses_state = self.generate_addresses_state(tx)
        addresses_state[self.alice.address].balance = 99
        addresses_state[self.alice.address].transaction_hashes = [tx.txhash]

        tx.revert_state_changes(addresses_state, self.unused_state_mock)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        self.assertEqual([], addresses_state[self.alice.address].transaction_hashes)
        addresses_state[self.alice.address].remove_lattice_pk.assert_called_once()

        m_revert_state_PK.assert_called_once()

    def test_revert_state_changes_empty_addresses_state(self, m_logger, m_apply_state_PK, m_revert_state_PK):
        tx = LatticePublicKey.create(**self.params)
        tx.sign(self.alice)
        addresses_state = {}

        tx.revert_state_changes(addresses_state, self.unused_state_mock)

        self.assertEqual({}, addresses_state)
        m_revert_state_PK.assert_called_once()
