# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.crypto.misc import address_from_extended_pk
from tests.misc.helper import get_alice_xmss, get_bob_xmss, with_pk_descriptor

logger.initialize_default()


class TestPublicKeyDescriptor(TestCase):
    """Test historical acceptance of non-canonical XMSS descriptors.

    The signature-type nibble and the third descriptor byte of an XMSS public
    key were never checked on mainnet. A transaction whose public key sets
    them is valid, and is sent from the address that key hashes to.
    """

    def setUp(self):
        self.alice = get_alice_xmss(4)
        self.bob = get_bob_xmss(4)

    def test_transfer_with_non_canonical_descriptor_is_valid(self):
        for signature_type, reserved in ((0, 1), (0, 0xFF), (2, 0), (0xF, 0x80)):
            pk = with_pk_descriptor(self.bob.pk, signature_type, reserved)
            tx = TransferTransaction.create(addrs_to=[self.alice.address],
                                            amounts=[100],
                                            message_data=None,
                                            fee=1,
                                            xmss_pk=pk)
            tx.sign(self.bob)

            self.assertTrue(tx.validate(), (signature_type, reserved))
            self.assertEqual(address_from_extended_pk(pk), tx.addr_from)
            self.assertNotEqual(self.bob.address, tx.addr_from)

            addresses = set()
            tx.set_affected_address(addresses)
            self.assertEqual({tx.addr_from, self.alice.address}, addresses)

    def test_one_signature_is_valid_under_each_descriptor(self):
        # The signed bytes do not cover the public key, so a signature made
        # once is valid with either descriptor. The two transactions differ
        # in hash and in the account they spend from.
        canonical = TransferTransaction.create(addrs_to=[self.alice.address],
                                               amounts=[100],
                                               message_data=None,
                                               fee=1,
                                               xmss_pk=self.bob.pk)
        canonical.sign(self.bob)

        other = TransferTransaction.create(addrs_to=[self.alice.address],
                                           amounts=[100],
                                           message_data=None,
                                           fee=1,
                                           xmss_pk=with_pk_descriptor(self.bob.pk, 0, 1))
        other._data.signature = canonical.signature
        other.update_txhash()

        self.assertTrue(canonical.validate())
        self.assertTrue(other.validate())
        self.assertNotEqual(canonical.txhash, other.txhash)
        self.assertEqual(self.bob.address, canonical.addr_from)
        self.assertNotEqual(canonical.addr_from, other.addr_from)

    def test_wrong_signer_rejected_whatever_the_descriptor(self):
        pk = with_pk_descriptor(self.bob.pk, 3, 9)
        tx = TransferTransaction.create(addrs_to=[self.alice.address],
                                        amounts=[100],
                                        message_data=None,
                                        fee=1,
                                        xmss_pk=pk)
        tx.sign(self.alice)
        self.assertFalse(tx.validate())

    def test_other_transaction_types(self):
        pk = with_pk_descriptor(self.bob.pk, 0, 1)

        message_tx = MessageTransaction.create(message_hash=b'hello', addr_to=None, fee=1, xmss_pk=pk)
        message_tx.sign(self.bob)
        self.assertTrue(message_tx.validate())
        self.assertEqual(address_from_extended_pk(pk), message_tx.addr_from)

        slave_tx = SlaveTransaction.create(slave_pks=[self.alice.pk], access_types=[0], fee=1, xmss_pk=pk)
        slave_tx.sign(self.bob)
        self.assertTrue(slave_tx.validate())
        self.assertEqual(address_from_extended_pk(pk), slave_tx.addr_from)

    def test_master_address_with_non_canonical_slave_key(self):
        pk = with_pk_descriptor(self.bob.pk, 0, 1)
        tx = TransferTransaction.create(addrs_to=[self.alice.address],
                                        amounts=[100],
                                        message_data=None,
                                        fee=1,
                                        xmss_pk=pk,
                                        master_addr=self.alice.address)
        tx.sign(self.bob)

        self.assertEqual(self.alice.address, tx.addr_from)
        self.assertEqual(address_from_extended_pk(pk), Transaction.get_slave(tx))

    def test_malformed_public_key_is_invalid_not_fatal(self):
        tx = TransferTransaction.create(addrs_to=[self.alice.address],
                                        amounts=[100],
                                        message_data=None,
                                        fee=1,
                                        xmss_pk=self.bob.pk)
        tx.sign(self.bob)
        tx._data.public_key = b''
        tx.update_txhash()

        self.assertFalse(tx.validate())
        with self.assertRaises(ValueError):
            _ = tx.addr_from
