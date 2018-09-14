# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import str2bin, XmssFast, bin2hstr, SHAKE_128, SHAKE_256, SHA2_256

from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS
from tests.misc.helper import get_alice_xmss

logger.initialize_default()


class TestXMSS(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestXMSS, self).__init__(*args, **kwargs)

    def test_sign_verify(self):
        message = "This is a test"
        message_bin = str2bin(message)

        xmss_height = 10
        seed = bytearray([i for i in range(48)])
        xmss = XMSS(XmssFast(seed, xmss_height))

        pk = xmss.pk

        xmss.set_ots_index(1)

        for i in range(10):
            self.assertTrue(xmss.ots_index == i + 1)
            signature = xmss.sign(message_bin)
            self.assertTrue(XmssFast.verify(message_bin, signature, pk))

    def test_PK(self):
        xmss_height = 10
        seed = bytearray([i for i in range(48)])
        xmss = XMSS(XmssFast(seed, xmss_height))

        pk = xmss.pk
        self.assertEqual('010500ffc6e502e2a8244aed6a8cd67531e79f95baa638615ba789c194a1d15d7eb'
                         '77e4e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e', bin2hstr(pk))

    def test_hash_function(self):
        xmss_height = 4
        seed = bytearray([i for i in range(48)])
        xmss = XMSS(XmssFast(seed, xmss_height, SHAKE_128))
        self.assertEqual('shake128', xmss.hash_function)

        xmss = XMSS(XmssFast(seed, xmss_height, SHAKE_256))
        self.assertEqual('shake256', xmss.hash_function)

        xmss = XMSS(XmssFast(seed, xmss_height, SHA2_256))
        self.assertEqual('sha2_256', xmss.hash_function)

    def test_signature_type(self):
        xmss_height = 4
        seed = bytearray([i for i in range(48)])
        xmss = XMSS(XmssFast(seed, xmss_height))
        self.assertEqual(0, xmss.signature_type)

    def test_from_height_custom_hash(self):
        xmss_height = 4
        xmss = XMSS.from_height(xmss_height, "shake128")
        self.assertEqual('shake128', xmss.hash_function)

    def test_get_height_from_sig_size(self):
        with self.assertRaises(Exception):
            XMSS.get_height_from_sig_size(2179)

        with self.assertRaises(Exception):
            XMSS.get_height_from_sig_size(0)

        with self.assertRaises(Exception):
            XMSS.get_height_from_sig_size(-1)

        height = XMSS.get_height_from_sig_size(3204)
        self.assertEqual(height, 32)

        height = XMSS.get_height_from_sig_size(2180)
        self.assertEqual(height, 0)

    def test_validate_signature(self):
        xmss = get_alice_xmss()
        xmss2 = get_alice_xmss(8)
        pk = xmss.pk
        signature = xmss.sign(b"hello")

        self.assertTrue(XMSS.validate_signature(signature, pk))

        with self.assertRaises(ValueError):
            XMSS.validate_signature(signature, None)

        self.assertFalse(XMSS.validate_signature(signature, xmss2.pk))
