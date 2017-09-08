# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from binascii import hexlify, unhexlify
from unittest import TestCase

from qrl.core import logger
from qrl.crypto.hmac_drbg import SEED, GEN, GEN_range, GEN_range_bin, new_keys
from tests.crypto.known_values import S1, S1_Pub, S1_Pri

logger.initialize_default(force_console_output=True)


# FIXME: These values test consistency. There is no golden value or second implementation to compare with.

class TestHMAC_DRBG(TestCase):
    S1 = unhexlify('7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4')

    def __init__(self, *args, **kwargs):
        super(TestHMAC_DRBG, self).__init__(*args, **kwargs)

    def test_SEED(self):
        r1 = SEED()
        r2 = SEED()
        self.assertNotEqual(r1, r2)
        self.assertEqual(len(r1), 48)
        self.assertEqual(len(r2), 48)
        r3 = SEED(100)
        self.assertEqual(len(r3), 100)

    def test_GEN(self):
        data = GEN(TestHMAC_DRBG.S1, 1)
        self.assertEqual(hexlify(data), '2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d')

        data = GEN(TestHMAC_DRBG.S1, 1)
        self.assertEqual(hexlify(data), '2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d')

        data = GEN(TestHMAC_DRBG.S1, 2)
        self.assertEqual(hexlify(data), '055ef7ba547c2db4af3e79fb53c9dc8871419a1fb8e4bf050b3c39abf6883e5d')

    def test_GEN_range(self):
        data = GEN_range(TestHMAC_DRBG.S1, 1, 5)

        expected = ['2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d',
                    '055ef7ba547c2db4af3e79fb53c9dc8871419a1fb8e4bf050b3c39abf6883e5d',
                    'be495e4351fcc0cd2d33b24b341ed1ab90386d13f4a683bb21e8926fc54a0407',
                    'fa76168597e6f2bc9df3a790c2c901f3147e0c270c06ff9abaf0d1b4353f7721',
                    '1fafc04d77de04ef956c4a729fe92852c197a90461ee3a10b8418097553164ca']

        self.assertEqual(expected, data)

    def test_GEN_range_bin(self):
        data = GEN_range_bin(TestHMAC_DRBG.S1, 1, 5)

        expected = ['2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d',
                    '055ef7ba547c2db4af3e79fb53c9dc8871419a1fb8e4bf050b3c39abf6883e5d',
                    'be495e4351fcc0cd2d33b24b341ed1ab90386d13f4a683bb21e8926fc54a0407',
                    'fa76168597e6f2bc9df3a790c2c901f3147e0c270c06ff9abaf0d1b4353f7721',
                    '1fafc04d77de04ef956c4a729fe92852c197a90461ee3a10b8418097553164ca']

        expected = [unhexlify(d) for d in expected]

        self.assertEqual(expected, data)

    def test_new_keys_random(self):
        seed1, pub1, priv1 = new_keys()
        seed2, pub2, priv2 = new_keys()

        self.assertNotEqual(seed1, S1)
        self.assertNotEqual(seed2, S1)
        self.assertNotEqual(seed1, seed2)
        self.assertNotEqual(pub1, pub2)
        self.assertNotEqual(priv1, priv2)

    def test_new_keys_known_seed(self):
        seed1, pub1, priv1 = new_keys(S1)

        self.assertEqual(hexlify(seed1), hexlify(S1))
        self.assertEqual(hexlify(pub1), hexlify(S1_Pub))
        self.assertEqual(hexlify(priv1), hexlify(S1_Pri))
