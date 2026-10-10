# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import hashlib
from unittest import TestCase

from pyqrllib.pyqrllib import QRLHelper

from qrl.crypto.misc import address_is_well_formed
from tests.misc.helper import MAINNET_UNKNOWN_HASH_FN_ADDRESS


def address_with_descriptor(descriptor: bytes) -> bytes:
    payload = descriptor + b'\xab' * 32
    return payload + hashlib.sha256(payload).digest()[-4:]


class TestAddressIsWellFormed(TestCase):
    def test_mainnet_address_with_unknown_hash_function(self):
        self.assertTrue(address_is_well_formed(MAINNET_UNKNOWN_HASH_FN_ADDRESS))

    def test_checksum_enforced(self):
        corrupted = bytearray(MAINNET_UNKNOWN_HASH_FN_ADDRESS)
        corrupted[-1] ^= 0xFF
        self.assertFalse(address_is_well_formed(bytes(corrupted)))

    def test_length_enforced(self):
        self.assertFalse(address_is_well_formed(b''))
        self.assertFalse(address_is_well_formed(MAINNET_UNKNOWN_HASH_FN_ADDRESS[:-1]))
        self.assertFalse(address_is_well_formed(MAINNET_UNKNOWN_HASH_FN_ADDRESS + b'\x00'))

    def test_non_bytes_rejected(self):
        self.assertFalse(address_is_well_formed(None))
        self.assertFalse(address_is_well_formed('Q' + '00' * 39))

    def test_only_address_format_is_checked_in_descriptor(self):
        # qrllib v1.2.4 accepted all of these, so consensus must too.
        for descriptor in (b'\x0c\x0d\x00',   # hash function 0xC
                           b'\x21\x00\x00',   # signature type 2
                           b'\x00\x00\x00',   # height 0
                           b'\x00\x02\x01',   # reserved byte set
                           b'\x11\x00\x00'):  # multi-sig
            self.assertTrue(address_is_well_formed(address_with_descriptor(descriptor)), descriptor.hex())

        self.assertFalse(address_is_well_formed(address_with_descriptor(b'\x00\x12\x00')))

    def test_matches_qrllib(self):
        # The pinned qrllib (>= 1.3.2) implements the same rule; if a future
        # qrllib drifts, this flags it even though consensus no longer depends on it.
        for address in (MAINNET_UNKNOWN_HASH_FN_ADDRESS,
                        address_with_descriptor(b'\x11\x00\x00'),
                        address_with_descriptor(b'\x00\x02\x01'),
                        address_with_descriptor(b'\x00\x12\x00')):
            self.assertEqual(QRLHelper.addressIsValid(address), address_is_well_formed(address), address.hex())
