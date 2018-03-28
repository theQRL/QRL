# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqryptonight.pyqryptonight import Qryptonight


class TestQryptonight(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestQryptonight, self).__init__(*args, **kwargs)

    def test_init(self):
        qn = Qryptonight()
        self.assertIsNotNone(qn)

    def test_hash(self):
        qn = Qryptonight()

        input = [0x03, 0x05, 0x07, 0x09]
        output = qn.hash(input)

        output_expected = (
            0x3E, 0xE5, 0x3F, 0xE1, 0xAC, 0xF3, 0x55, 0x92,
            0x66, 0xD8, 0x43, 0x89, 0xCE, 0xDE, 0x99, 0x33,
            0xC6, 0x8F, 0xC5, 0x1E, 0xD0, 0xA6, 0xC7, 0x91,
            0xF8, 0xF9, 0xE8, 0x9D, 0xB6, 0x23, 0xF0, 0xF6
        )

        self.assertEqual(output_expected, output)

    def test_hash2(self):
        qn = Qryptonight()

        input = [0x03, 0x05, 0x07, 0x09] * 30
        output = qn.hash(input)

        output_expected = (168, 11, 50, 111, 10, 254, 21, 185, 222, 10, 243,
                           35, 106, 150, 44, 209, 21, 58, 1, 186, 182, 211,
                           60, 241, 74, 98, 85, 168, 56, 23, 141, 181)

        self.assertEqual(output_expected, output)

    def test_hash3(self):
        qn = Qryptonight()

        input = [0x03, 0x05, 0x07, 0x09] * 200
        output = qn.hash(input)

        output_expected = (2, 218, 202, 93, 168, 126, 221, 156, 39,
                           7, 130, 68, 248, 167, 50, 112, 164, 176,
                           94, 88, 61, 129, 92, 37, 226, 89, 110,
                           39, 129, 219, 4, 164)

        self.assertEqual(output_expected, output)
