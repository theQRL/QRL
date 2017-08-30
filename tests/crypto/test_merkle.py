# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from binascii import hexlify, unhexlify
from unittest import TestCase

from timeout_decorator import timeout_decorator

from qrl.core import logger
from qrl.crypto.hmac_drbg import new_keys, SEED
from qrl.crypto.misc import xmss_tree
from qrl.crypto.mnemonic import seed_to_mnemonic
from qrl.crypto.xmss import XMSS

logger.initialize_default(force_console_output=True)


# FIXME: These values test consistency. There is no golden value or second implementation to compare with.

class TestMerkle(TestCase):
    S1 = unhexlify('7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4')

    S1_Pub = unhexlify(
        '6b424d99242a1a3f40f60bf565b1a63aed94464b26ad022eed800ec3384f11fe40c46dc60cdf80d60dc75b4c908b4afa')
    S1_Pri = unhexlify(
        '2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32daaa7b50f313b3c93743a00f027af0551')

    S1_Mne = 'lacoca breech scowed lunier towdie livery burree gambit tagua arabia duali tikkun doodah airier ' \
             'soho quanti merd trees fascia correo adams eldin taiga praxis zymite dyce pavise alant layed ' \
             'yenned copart mesked'

    S1_PK = ['18e9198ac177807cc249e29b3d0cdda14b688d2cb8387e782239c0a565faee35',
             ['6fb23184bce2fe956d4996f582f9981abef4d2577124490fec021108f9c9b1fd',
              '6d6a6eae1bf5ca84d6bb0290f829f0896aa01d3a0dfbc8c937cd7158901182bc'],
             ['e101a4902a5090ab19f655791eb735a81e07d7282b58fce2c9a597209c29ce51',
              '6cb7f6b8a0b4e9797d6826096879f23a2feba90932892e27ad7cc984d908b336',
              'f8920b0716c163f5df4c128585ffa806185b940d1e0f5c3cde981bc1c47804c6',
              '523680e0dc7b9849c698cae32e6ecaafdc81c4f9c7122cc7a8b2b09fb62b41c7',
              '5d34a509f71e74ef3dc59ba327d6a49da321c5a7c01d243f1861554ff1e74456',
              '3d1f93175aa8b1dc5f7263fc8d53615e25a3f29b4866426195840a5dbd4fe752',
              'eeb56bcbd28a6e51f7f4d63dc584afe333ec037f6cd2b0bd05c808ab25b978f0',
              'c5d48dee1eb76147ca1423fc4dc47a089c668232f985643140fd8d323e1425fd',
              '00b09fdb2dd3bb5d882b30d2aebdef010cccd06c0891d481ea44b2177d9b73d9',
              'c93cd5cbd16d5ce80c12013bbf850bb72f11493382e8307191898d1d30769e8e',
              '95f11edd37c0c79e188aa3b50fae08b0d361ea0bf478bfd76896992f0ba954a5',
              'd7c9a1fc3240517feed3f42591edff8b5a24699d95a12f0fef79c577ba464ab0',
              'fe7d0181f05df53df1d8f4a9a039971bbf933ab0b6995855f5860fd699d662c4',
              'f8dfd075baec6e8ba69bcf64fc33b2719eeb22952180f2819a67bf84e3a0e34e']]

    S1_PKsh = ['18e9198ac177807cc249e29b3d0cdda14b688d2cb8387e782239c0a565faee35',
               '6b424d99242a1a3f40f60bf565b1a63aed94464b26ad022eed800ec3384f11fe'
               '40c46dc60cdf80d60dc75b4c908b4afa']

    S1_catPK = ['18e9198ac177807cc249e29b3d0cdda14b688d2cb8387e782239c0a565faee35',
                '6fb23184bce2fe956d4996f582f9981abef4d2577124490fec021108f9c9b1fd'
                '6d6a6eae1bf5ca84d6bb0290f829f0896aa01d3a0dfbc8c937cd7158901182bc',
                'e101a4902a5090ab19f655791eb735a81e07d7282b58fce2c9a597209c29ce51'
                '6cb7f6b8a0b4e9797d6826096879f23a2feba90932892e27ad7cc984d908b336'
                'f8920b0716c163f5df4c128585ffa806185b940d1e0f5c3cde981bc1c47804c6'
                '523680e0dc7b9849c698cae32e6ecaafdc81c4f9c7122cc7a8b2b09fb62b41c7'
                '5d34a509f71e74ef3dc59ba327d6a49da321c5a7c01d243f1861554ff1e74456'
                '3d1f93175aa8b1dc5f7263fc8d53615e25a3f29b4866426195840a5dbd4fe752'
                'eeb56bcbd28a6e51f7f4d63dc584afe333ec037f6cd2b0bd05c808ab25b978f0'
                'c5d48dee1eb76147ca1423fc4dc47a089c668232f985643140fd8d323e1425fd'
                '00b09fdb2dd3bb5d882b30d2aebdef010cccd06c0891d481ea44b2177d9b73d9'
                'c93cd5cbd16d5ce80c12013bbf850bb72f11493382e8307191898d1d30769e8e'
                '95f11edd37c0c79e188aa3b50fae08b0d361ea0bf478bfd76896992f0ba954a5'
                'd7c9a1fc3240517feed3f42591edff8b5a24699d95a12f0fef79c577ba464ab0'
                'fe7d0181f05df53df1d8f4a9a039971bbf933ab0b6995855f5860fd699d662c4'
                'f8dfd075baec6e8ba69bcf64fc33b2719eeb22952180f2819a67bf84e3a0e34e']

    S1_catPKsh = '18e9198ac177807cc249e29b3d0cdda14b688d2cb8387e782239c0a565faee3' \
                 '56b424d99242a1a3f40f60bf565b1a63aed94464b26ad022eed800ec3384f11' \
                 'fe40c46dc60cdf80d60dc75b4c908b4afa'

    S1_root = '18e9198ac177807cc249e29b3d0cdda14b688d2cb8387e782239c0a565faee35'
    S1_addr = 'Q385d6b85063d6f3593f6de6982bb9dd9c8fc92fc54ed67879f6c92c6cf53473d124a'
    S1_addrlong = 'Qa1f72a319c6881dd29a673d1cc5870bba445a0289a3a75641548c60f15a264de97da'

    def __init__(self, *args, **kwargs):
        super(TestMerkle, self).__init__(*args, **kwargs)

    def test_new_keys_random(self):
        seed1, pub1, priv1 = new_keys()
        seed2, pub2, priv2 = new_keys()

        self.assertNotEqual(seed1, TestMerkle.S1)
        self.assertNotEqual(seed2, TestMerkle.S1)
        self.assertNotEqual(seed1, seed2)
        self.assertNotEqual(pub1, pub2)
        self.assertNotEqual(priv1, priv2)

    def test_new_keys_known_seed(self):
        seed1, pub1, priv1 = new_keys(TestMerkle.S1)

        self.assertEqual(hexlify(seed1), hexlify(TestMerkle.S1))
        self.assertEqual(hexlify(pub1), hexlify(TestMerkle.S1_Pub))
        self.assertEqual(hexlify(priv1), hexlify(TestMerkle.S1_Pri))

    def test_seed_to_mnemonic_random(self):
        r_seed1 = SEED()
        r_seed2 = SEED()
        mnemonic1 = seed_to_mnemonic(r_seed1)
        mnemonic2 = seed_to_mnemonic(r_seed2)

        self.assertNotEqual(mnemonic1, TestMerkle.S1_Mne)
        self.assertNotEqual(mnemonic2, TestMerkle.S1_Mne)
        self.assertNotEqual(mnemonic1, mnemonic2)

    def test_seed_to_mnemonic_known(self):
        mnemonic = seed_to_mnemonic(TestMerkle.S1)
        self.assertEqual(mnemonic, TestMerkle.S1_Mne)

    def test_xmss_tree(self):
        # Create seeds from public/private keys
        seed1, pub1, priv1 = new_keys(TestMerkle.S1)
        xmss_array, x_bms, l_bms, privs, pubs = xmss_tree(2, public_SEED=pub1, private_SEED=priv1)

        # Verify sizes
        self.assertEqual(len(xmss_array), 2)
        self.assertEqual(len(x_bms), 5)
        self.assertEqual(len(l_bms), 14)
        self.assertEqual(len(privs), 2)
        self.assertEqual(len(pubs), 2)

    def test_XMSS_get_address_random(self):
        xmss1 = XMSS(signatures=1, SEED=None)
        xmss2 = XMSS(signatures=1, SEED=None)

        self.assertEqual(xmss1.signatures, 1)
        self.assertEqual(xmss2.signatures, 1)
        self.assertNotEqual(xmss1.root, xmss2.root)
        self.assertNotEqual(xmss1.address, xmss2.address)

    @timeout_decorator.timeout(5)
    def test_XMSS_get_address_known(self):
        xmss1 = XMSS(signatures=1, SEED=TestMerkle.S1)
        self.assertEqual(xmss1.signatures, 1)
        self.assertEqual(xmss1.root, TestMerkle.S1_root)
        self.assertEqual(xmss1.address, TestMerkle.S1_addr)
        self.assertEqual(xmss1.PK, TestMerkle.S1_PK)
        self.assertEqual(xmss1.PK_short, TestMerkle.S1_PKsh)
        self.assertEqual(xmss1.catPK, TestMerkle.S1_catPK)
        self.assertEqual(xmss1.catPK_short, TestMerkle.S1_catPKsh)
        self.assertEqual(xmss1.address_long, TestMerkle.S1_addrlong)

        # Test the same second time to check for independency
        xmss2 = XMSS(signatures=1, SEED=TestMerkle.S1)
        self.assertEqual(xmss2.signatures, 1)
        self.assertEqual(xmss2.root, TestMerkle.S1_root)
        self.assertEqual(xmss2.address, TestMerkle.S1_addr)
        self.assertEqual(xmss2.PK, TestMerkle.S1_PK)
        self.assertEqual(xmss2.PK_short, TestMerkle.S1_PKsh)
        self.assertEqual(xmss2.catPK, TestMerkle.S1_catPK)
        self.assertEqual(xmss2.catPK_short, TestMerkle.S1_catPKsh)
        self.assertEqual(xmss2.address_long, TestMerkle.S1_addrlong)

        xmss3 = XMSS(signatures=5, SEED=TestMerkle.S1)
        self.assertEqual(xmss3.signatures, 5)
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
