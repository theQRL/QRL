from unittest import TestCase

from mock import patch

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.txs.LatticeTransaction import LatticeTransaction
from tests.misc.helper import get_alice_xmss, get_bob_xmss

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestLatticeTransaction(TestCase):

    def setUp(self):
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

    def test_validate_tx_max_size(self, m_logger):
        pk1 = b'0' * config.dev.lattice_pk1_max_length
        pk2 = b'0' * config.dev.lattice_pk2_max_length
        pk3 = b'0' * config.dev.lattice_pk3_max_length

        tx = LatticeTransaction.create(pk1=pk1,
                                       pk2=pk2,
                                       pk3=pk3,
                                       fee=2**64-1,
                                       xmss_pk=self.alice.pk,
                                       master_addr=self.bob.address)
        tx._data.nonce = 2**64 - 1
        tx.sign(self.alice)
        tx._data.signature = b'8' * 3140  # max expected signature size based on height 30

        self.assertEqual(tx.size, tx.max_size_limit)
        self.assertTrue(tx._validate_custom())

    def test_validate_tx_exceeds_max_size(self, m_logger):
        pk1 = b'0' * config.dev.lattice_pk1_max_length
        pk2 = b'0' * config.dev.lattice_pk2_max_length
        pk3 = b'0' * config.dev.lattice_pk3_max_length

        tx = LatticeTransaction.create(pk1=pk1,
                                       pk2=pk2,
                                       pk3=pk3,
                                       fee=2**64-1,
                                       xmss_pk=self.alice.pk,
                                       master_addr=self.bob.address)
        tx._data.nonce = 2**64 - 1
        tx.sign(self.alice)
        tx._data.signature = b'8' * 3141  # 1 byte over max expected signature size

        self.assertGreater(tx.size, tx.max_size_limit)
        self.assertFalse(tx._validate_custom())