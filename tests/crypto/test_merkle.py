# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from timeout_decorator import timeout_decorator

from qrl.core import logger
from qrl.crypto.hmac_drbg import new_keys
from qrl.crypto.xmss import XMSS
from tests.crypto.known_values import S1, S1_root, S1_addrlong, S1_catPKsh, S1_catPK, S1_PKsh, \
    S1_PK, S1_addr

logger.initialize_default(force_console_output=True)


# FIXME: These values test consistency. There is no golden value or second implementation to compare with.

class TestMerkle(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMerkle, self).__init__(*args, **kwargs)

    def test_xmss_tree(self):
        # Create seeds from public/private keys
        seed1, pub1, priv1 = new_keys(S1)
        xmss_array, x_bms, l_bms, privs, pubs = XMSS._xmss_tree(number_signatures=2,
                                                                public_SEED=pub1,
                                                                private_SEED=priv1)

        # Verify sizes
        self.assertEqual(len(xmss_array), 2)
        self.assertEqual(len(x_bms), 5)
        self.assertEqual(len(l_bms), 14)
        self.assertEqual(len(privs), 2)
        self.assertEqual(len(pubs), 2)

    def test_xmss_get_address_random(self):
        xmss1 = XMSS(number_signatures=1, SEED=None)
        xmss2 = XMSS(number_signatures=1, SEED=None)

        self.assertEqual(xmss1.number_signatures, 1)
        self.assertEqual(xmss2.number_signatures, 1)
        self.assertNotEqual(xmss1.root, xmss2.root)
        self.assertNotEqual(xmss1.address, xmss2.address)

    @timeout_decorator.timeout(5)
    def test_xmss_get_address_known(self):
        xmss1 = XMSS(number_signatures=1, SEED=S1)
        self.assertEqual(xmss1.number_signatures, 1)
        self.assertEqual(xmss1.root, S1_root)
        self.assertEqual(xmss1.address, S1_addr)
        self.assertEqual(xmss1.PK, S1_PK)
        self.assertEqual(xmss1.PK_short, S1_PKsh)
        self.assertEqual(xmss1.catPK, S1_catPK)
        self.assertEqual(xmss1.catPK_short, S1_catPKsh)
        self.assertEqual(xmss1.address_long, S1_addrlong)

        # Test the same second time to check for independency
        xmss2 = XMSS(number_signatures=1, SEED=S1)
        self.assertEqual(xmss2.number_signatures, 1)
        self.assertEqual(xmss2.root, S1_root)
        self.assertEqual(xmss2.address, S1_addr)
        self.assertEqual(xmss2.PK, S1_PK)
        self.assertEqual(xmss2.PK_short, S1_PKsh)
        self.assertEqual(xmss2.catPK, S1_catPK)
        self.assertEqual(xmss2.catPK_short, S1_catPKsh)
        self.assertEqual(xmss2.address_long, S1_addrlong)

        xmss3 = XMSS(number_signatures=5, SEED=S1)
        self.assertEqual(xmss3.number_signatures, 5)
        self.assertIsNotNone(xmss3.address)
        self.assertEqual(xmss3.root, 'befa9094da96ad69015bebbf63d3ec1d9a0309e714d135f0c1dd3d9a2c9f4a57')
        self.assertEqual(xmss3.address, 'Q54ec65785ae34c4fbe9f33db3b8a1027d5f9c58c4398cfde43060a83dca7b59baf0e')

        # TODO: Test other values
        # print(xmss1.PK)
        # print(xmss1.PK_short)
        # print(xmss1.catPK)
        # print(xmss1.catPK_short)
        # print(xmss1.address_long)

        # TODO: Enable high limit check once performance is good enough
        # new = merkle.XMSS(signatures=9000, SEED=None)
        # self.assertEqual(new.signatures, 8000)
        # self.assertIsNotNone(new.address)
