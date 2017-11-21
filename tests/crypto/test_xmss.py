# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import str2bin

from qrl.core import logger
from qrl.crypto.xmss import XMSS

logger.initialize_default(force_console_output=True)


class TestXMSS(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestXMSS, self).__init__(*args, **kwargs)

    def test_sign_verify(self):
        message = "This is a test"
        message_bin = str2bin(message)

        xmss_height = 10
        seed = bytearray([i for i in range(48)])
        xmss = XMSS(xmss_height, seed)

        pk = xmss.pk()

        xmss.set_index(1)

        for i in range(10):
            self.assertTrue(xmss.get_index() == i + 1)
            signature = xmss.SIGN(message_bin)
            self.assertTrue(XMSS.VERIFY(message_bin, signature, pk))
