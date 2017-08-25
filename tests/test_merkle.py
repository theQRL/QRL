# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from binascii import hexlify, unhexlify
from unittest import TestCase

from timeout_decorator import timeout_decorator

from qrlcore import logger, merkle
from qrlcore.merkle import xmss_tree

logger.initialize_default(force_console_output=True)


class TestMerkle(TestCase):
    S_1 = unhexlify('7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4')

    S_1Pub = unhexlify(
        '6b424d99242a1a3f40f60bf565b1a63aed94464b26ad022eed800ec3384f11fe40c46dc60cdf80d60dc75b4c908b4afa')
    S_1Pri = unhexlify(
        '2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32daaa7b50f313b3c93743a00f027af0551')

    S_1Mne = 'lacoca breech scowed lunier towdie livery burree gambit tagua arabia duali tikkun doodah airier ' \
             'soho quanti merd trees fascia correo adams eldin taiga praxis zymite dyce pavise alant layed ' \
             'yenned copart mesked'

    def __init__(self, *args, **kwargs):
        super(TestMerkle, self).__init__(*args, **kwargs)

    def test_SEED(self):
        r1 = merkle.SEED()
        r2 = merkle.SEED()
        self.assertNotEqual(r1, r2)
        self.assertEqual(len(r1), 48)
        self.assertEqual(len(r2), 48)
        r3 = merkle.SEED(100)
        self.assertEqual(len(r3), 100)

    def test_GEN(self):
        data = merkle.GEN(TestMerkle.S_1, 1)
        self.assertEqual(hexlify(data), '2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d')

        data = merkle.GEN(TestMerkle.S_1, 1)
        self.assertEqual(hexlify(data), '2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d')

        data = merkle.GEN(TestMerkle.S_1, 2)
        self.assertEqual(hexlify(data), '055ef7ba547c2db4af3e79fb53c9dc8871419a1fb8e4bf050b3c39abf6883e5d')

    def test_GEN_range(self):
        data = merkle.GEN_range(TestMerkle.S_1, 1, 5)

        expected = ['2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d',
                    '055ef7ba547c2db4af3e79fb53c9dc8871419a1fb8e4bf050b3c39abf6883e5d',
                    'be495e4351fcc0cd2d33b24b341ed1ab90386d13f4a683bb21e8926fc54a0407',
                    'fa76168597e6f2bc9df3a790c2c901f3147e0c270c06ff9abaf0d1b4353f7721',
                    '1fafc04d77de04ef956c4a729fe92852c197a90461ee3a10b8418097553164ca']

        self.assertEqual(expected, data)

    def test_GEN_range_bin(self):
        data = merkle.GEN_range_bin(TestMerkle.S_1, 1, 5)

        expected = ['2c4147cd5c75622220054bd8923ba565999931634499fc096c0b9cedf8f4f32d',
                    '055ef7ba547c2db4af3e79fb53c9dc8871419a1fb8e4bf050b3c39abf6883e5d',
                    'be495e4351fcc0cd2d33b24b341ed1ab90386d13f4a683bb21e8926fc54a0407',
                    'fa76168597e6f2bc9df3a790c2c901f3147e0c270c06ff9abaf0d1b4353f7721',
                    '1fafc04d77de04ef956c4a729fe92852c197a90461ee3a10b8418097553164ca']

        expected = [unhexlify(d) for d in expected]

        self.assertEqual(expected, data)

    def test_new_keys_random(self):
        seed1, pub1, priv1 = merkle.new_keys()
        seed2, pub2, priv2 = merkle.new_keys()

        self.assertNotEqual(seed1, TestMerkle.S_1)
        self.assertNotEqual(seed2, TestMerkle.S_1)
        self.assertNotEqual(seed1, seed2)
        self.assertNotEqual(pub1, pub2)
        self.assertNotEqual(priv1, priv2)

    def test_new_keys_known_seed(self):
        seed1, pub1, priv1 = merkle.new_keys(TestMerkle.S_1)

        self.assertEqual(hexlify(seed1), hexlify(TestMerkle.S_1))
        self.assertEqual(hexlify(pub1), hexlify(TestMerkle.S_1Pub))
        self.assertEqual(hexlify(priv1), hexlify(TestMerkle.S_1Pri))

    def test_seed_to_mnemonic_random(self):
        r_seed1 = merkle.SEED()
        r_seed2 = merkle.SEED()
        mnemonic1 = merkle.seed_to_mnemonic(r_seed1)
        mnemonic2 = merkle.seed_to_mnemonic(r_seed2)

        self.assertNotEqual(mnemonic1, TestMerkle.S_1Mne)
        self.assertNotEqual(mnemonic2, TestMerkle.S_1Mne)
        self.assertNotEqual(mnemonic1, mnemonic2)

    def test_seed_to_mnemonic_known(self):
        mnemonic = merkle.seed_to_mnemonic(TestMerkle.S_1)
        self.assertEqual(mnemonic, TestMerkle.S_1Mne)

    def test_xmss_tree(self):
        # Create seeds from public/private keys
        seed1, pub1, priv1 = merkle.new_keys(TestMerkle.S_1)
        xmss_array, x_bms, l_bms, privs, pubs = xmss_tree(2, public_SEED=pub1, private_SEED=priv1)

        # Verify sizes
        self.assertEqual(len(xmss_array), 2)
        self.assertEqual(len(x_bms), 5)
        self.assertEqual(len(l_bms), 14)
        self.assertEqual(len(privs), 2)
        self.assertEqual(len(pubs), 2)

    def test_XMSS_get_address_random(self):
        xmss1 = merkle.XMSS(signatures=1, SEED=None)
        xmss2 = merkle.XMSS(signatures=1, SEED=None)

        self.assertEqual(xmss1.signatures, 1)
        self.assertEqual(xmss2.signatures, 1)
        self.assertNotEqual(xmss1.root, xmss2.root)
        self.assertNotEqual(xmss1.address, xmss2.address)

    @timeout_decorator.timeout(5)
    def test_XMSS_get_address_known(self):
        xmss = merkle.XMSS(signatures=1, SEED=TestMerkle.S_1)
        self.assertEqual(xmss.signatures, 1)
        self.assertEqual(xmss.root, '18e9198ac177807cc249e29b3d0cdda14b688d2cb8387e782239c0a565faee35')
        self.assertEqual(xmss.address, 'Q385d6b85063d6f3593f6de6982bb9dd9c8fc92fc54ed67879f6c92c6cf53473d124a')

        new = merkle.XMSS(signatures=5, SEED=None)
        self.assertEqual(new.signatures, 5)
        self.assertIsNotNone(new.address)

        # TODO: Enable high limit check once performance is good enough
        # new = merkle.XMSS(signatures=9000, SEED=None)
        # self.assertEqual(new.signatures, 8000)
        # self.assertIsNotNone(new.address)
