# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import hashlib
from unittest import TestCase

from pyqrllib.pyqrllib import QRLHelper

from qrl.crypto.misc import address_is_well_formed, address_from_extended_pk, extended_pk_for_verification
from qrl.crypto.xmss import XMSS
from pyqrllib.pyqrllib import XmssFast, SHA2_256, SHAKE_128, SHAKE_256
from tests.misc.helper import MAINNET_UNKNOWN_HASH_FN_ADDRESS, get_alice_xmss, get_bob_xmss, with_pk_descriptor

# Addresses qrllib v1.2.4 derives for one key (get_bob_xmss(4)) under different
# descriptor bytes, computed with pyqrllib 1.2.4. v1.2.4 also verifies a
# signature made by the key against every one of these public keys.
BOB_PK_HEIGHT_4 = '010200b065494728a23bc8e81db6385591b5ae81dadf5bb99f163e213c55d6331d0b7f' \
                  '10dc367cd0ea29671de422211a887fb3d199b0a7f1b3c02faa62adc34d3a5dab'
QRLLIB_1_2_4_ADDRESSES = [
    ('010200', '010200c953237a46eca933e9dd2cf273860ef9d4542ae3d0b4326a07888983cacf9a8f91bc39ef'),
    ('010207', '010200082c9f34c825793a467d3b16775db0aa31e7b263fe68128eb9c53f3f97481f1426212452'),
    ('0102c3', '0102000dd240075f3e68ddd912e34cbc02649edfa6da741cd60bc79da9f6b84d0211d436546215'),
    ('510200', '0102001f51f740c5a8aa1c9d0e13c0ab621591dc8da83d152b7fe6723aa2e649a0c1e04a84bb2e'),
    ('110200', '0102006f37197ddb7d873a789a0b691f61e2c03448ccf2898c0354d3f9953b44705cb9142a168f'),
    ('e1024a', '010200bf78029ecd2171f7365514ece7071690fec70543519de1f6a1f96ba80ac232defd5cbf33'),
]


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


class TestAddressFromExtendedPK(TestCase):
    def test_test_key_is_the_one_the_vectors_were_made_with(self):
        self.assertEqual(BOB_PK_HEIGHT_4, get_bob_xmss(4).pk.hex())

    def test_matches_qrllib_1_2_4_vectors(self):
        pk = bytes.fromhex(BOB_PK_HEIGHT_4)
        for descriptor, address in QRLLIB_1_2_4_ADDRESSES:
            candidate = bytes.fromhex(descriptor) + pk[3:]
            self.assertEqual(address, address_from_extended_pk(candidate).hex(), descriptor)

    def test_matches_qrllib_for_canonical_keys(self):
        # For keys with a canonical descriptor every qrllib version agrees with the in-tree rule.
        seed = bytes(range(100, 148))
        for hash_function in (SHA2_256, SHAKE_128, SHAKE_256):
            for height in (4, 6, 8):
                xmss = XMSS(XmssFast(seed, height, hash_function))
                self.assertEqual(xmss.address, address_from_extended_pk(xmss.pk), (hash_function, height))

    def test_each_descriptor_variant_has_its_own_well_formed_address(self):
        pk = get_bob_xmss(4).pk
        addresses = set()
        for signature_type in range(16):
            for reserved in (0, 1, 0x80, 0xFF):
                address = address_from_extended_pk(with_pk_descriptor(pk, signature_type, reserved))
                self.assertTrue(address_is_well_formed(address))
                # The address descriptor is normalised; only the hash differs.
                self.assertEqual(bytes([pk[0] & 0x0F, pk[1] & 0x0F, 0]), address[:3])
                addresses.add(address)
        self.assertEqual(16 * 4, len(addresses))

    def test_wrong_size_rejected(self):
        pk = get_bob_xmss(4).pk
        for candidate in (b'', pk[:-1], pk + b'\x00', None, pk.hex()):
            with self.assertRaises(ValueError):
                address_from_extended_pk(candidate)

    def test_unsupported_address_format_rejected(self):
        pk = get_bob_xmss(4).pk
        for address_format in range(1, 16):
            candidate = bytes([pk[0], (address_format << 4) | (pk[1] & 0x0F), 0]) + pk[3:]
            with self.assertRaises(ValueError):
                address_from_extended_pk(candidate)


class TestExtendedPKForVerification(TestCase):
    def test_canonical_key_unchanged(self):
        pk = get_bob_xmss(4).pk
        self.assertEqual(pk, extended_pk_for_verification(pk))

    def test_only_signature_type_and_third_byte_cleared(self):
        pk = get_bob_xmss(4).pk
        self.assertEqual(pk, extended_pk_for_verification(with_pk_descriptor(pk, 0xF, 0xFF)))

        # Hash function, height and address format are left for the library to judge.
        other = bytes([0x0C, 0x1D, 0x00]) + pk[3:]
        self.assertEqual(other, extended_pk_for_verification(other))

    def test_wrong_size_passed_through(self):
        for candidate in (b'', b'\xff' * 66, b'\xff' * 68):
            self.assertEqual(candidate, extended_pk_for_verification(candidate))

    def test_signature_verifies_under_every_descriptor_variant(self):
        # qrllib v1.2.4 ignored these two fields when verifying, so one
        # signature is valid for each of them.
        xmss = get_bob_xmss(4)
        message = bytes([7]) * 32
        signature = xmss.sign(message)
        for descriptor, _ in QRLLIB_1_2_4_ADDRESSES:
            candidate = bytes.fromhex(descriptor) + xmss.pk[3:]
            self.assertTrue(XmssFast.verify(message, signature, extended_pk_for_verification(candidate)), descriptor)

    def test_signature_from_another_key_still_rejected(self):
        message = bytes([7]) * 32
        signature = get_alice_xmss(4).sign(message)
        candidate = with_pk_descriptor(get_bob_xmss(4).pk, 5, 7)
        self.assertFalse(XmssFast.verify(message, signature, extended_pk_for_verification(candidate)))
