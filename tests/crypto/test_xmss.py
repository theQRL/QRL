# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import str2bin, XmssFast, bin2hstr

from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS

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
