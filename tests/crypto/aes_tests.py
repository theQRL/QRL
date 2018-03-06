# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import hstr2bin

from qrl.core.misc import logger
from qrl.crypto.AESHelper import AESHelper

logger.initialize_default()


class TestAES(TestCase):
    MNEMONIC_SECRET = 'wfRacet4veDw0s4O3Y/RYej+2C3S7Dsrzx0H2/cH6TU0dLQmPyOI9tK+YcPAnEbrqni/KcCNKP' \
                      'xV0l3vCtWdy58aCYbr2yf39VGsvJvWaWrFMcOWRJ3x2QUS86cy89JNijQysvm3M670gTJ2Vr9L' \
                      'hGMGIT7095JczFYNq6WoTzciljWIk5NkLwa8lWBXCmDn5u/ogWkLC9eTdPITPc7rZEAgB3uZKh' \
                      'Vq08LfdNNyGdi/rIvb9CdCrDqN+H4DgpqcBlrPw6c7rJ1zHOqUSQOeP62FrWQbc6wmew=='
    MNEMONIC_PLAINTEXT = 'absorb drank fruity set aside earth sacred she junior over daisy trend rude huge blew ' \
                         'size stem sticky baron lowest robert spicy friar clear elude knack invoke buggy volume ' \
                         'pit plead paris drift highly'

    def __init__(self, *args, **kwargs):
        super(TestAES, self).__init__(*args, **kwargs)

    def test_base64(self):
        pass

    def test_mnemonic_encrypt(self):
        key = 'test1234'
        iv = bytes(hstr2bin('c1f45a71eb78bde0f0d2ce0edd8fd161'))  # Fix it so tests are reproducible

        walletAES = AESHelper(key)
        message = self.MNEMONIC_PLAINTEXT.encode()
        ciphertext = walletAES.encrypt(message, iv)

        self.assertEqual(self.MNEMONIC_SECRET, ciphertext)

    def test_mnemonic_decrypt(self):
        key = 'test1234'

        walletAES = AESHelper(key)
        message = walletAES.decrypt(self.MNEMONIC_SECRET)

        message = message.decode()
        self.assertEqual(self.MNEMONIC_PLAINTEXT, message)
