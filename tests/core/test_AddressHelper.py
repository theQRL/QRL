from unittest import TestCase

from qrl.core import AddressHelper
from tests.misc.helper import get_alice_xmss

alice = get_alice_xmss()


# Q010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f
# q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26

class TestBech32Conversion(TestCase):
    def test_pk_to_b32address(self):
        b32 = AddressHelper.pk_to_b32address(alice.pk)
        self.assertEqual(b32, 'q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26')

    def test_raw_to_b32address(self):
        b32 = AddressHelper.raw_to_b32address(alice.address)
        self.assertEqual(b32, 'q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26')

    def test_raw_to_hexaddress(self):
        address_hex = AddressHelper.raw_to_hexaddress(alice.address)
        self.assertEqual(alice.qaddress, address_hex)

    def test_hex_to_b32address(self):
        b32 = AddressHelper.hex_to_b32address(alice.qaddress)
        self.assertEqual(b32, 'q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26')

    def test_hex_to_rawaddress(self):
        address_raw = AddressHelper.hex_to_rawaddress(
            'Q010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f')
        self.assertEqual(address_raw, alice.address)

    def test_b32_to_rawaddress(self):
        address_raw = AddressHelper.b32_to_rawaddress(
            'q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26')
        self.assertEqual(address_raw, alice.address)

    def test_b32_to_hexaddress(self):
        address_hex = AddressHelper.b32_to_hexaddress(
            'q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26')
        self.assertEqual(address_hex, 'Q010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f')

    def test_any_to_rawaddress(self):
        address_raw = AddressHelper.any_to_rawaddress(
            'Q010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f')
        self.assertEqual(address_raw, alice.address)

        address_raw = AddressHelper.any_to_rawaddress(
            'q1qypspgw6ya8x3jytpn85frstryt057ymq84ja48f44t9ecnyeyus0q4fq6pu26')
        self.assertEqual(address_raw, alice.address)
