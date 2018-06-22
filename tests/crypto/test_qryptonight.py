# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger
from pyqryptonight.pyqryptonight import Qryptonight, UInt256ToString

logger.initialize_default()


class TestQryptonight(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestQryptonight, self).__init__(*args, **kwargs)

    def test_init(self):
        qn = Qryptonight()
        self.assertIsNotNone(qn)

    def test_hash(self):
        qn = Qryptonight()

        input = [0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09,
                 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09,
                 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07]
        output = qn.hash(input)

        output_expected = (
            0x96, 0x76, 0x53, 0x26, 0x2F, 0x9B, 0x15, 0x90,
            0xB9, 0x88, 0x0F, 0x64, 0xA3, 0x80, 0x8C, 0x4B,
            0x01, 0xEA, 0x29, 0x2C, 0x48, 0xFC, 0x7C, 0x47,
            0x0D, 0x25, 0x50, 0x00, 0x57, 0xCA, 0x07, 0x70,
        )

        self.assertEqual(output_expected, output)

    def test_hash2(self):
        qn = Qryptonight()

        input = [0x03, 0x05, 0x07, 0x09] * 30
        output = qn.hash(input)

        output_expected = (255, 253, 83, 78, 29, 24, 160, 224, 30, 240, 158,
                           39, 233, 125, 90, 170, 78, 59, 157, 146, 97, 86,
                           205, 161, 160, 155, 48, 144, 51, 148, 155, 99)

        self.assertEqual(output_expected, output)

    def test_hash3(self):
        qn = Qryptonight()

        input = [0x03, 0x05, 0x07, 0x09] * 200
        output = qn.hash(input)

        output_expected = (216, 31, 227, 138, 9, 118, 5, 200, 136,
                           40, 156, 168, 86, 35, 146, 223, 199, 76,
                           188, 213, 25, 117, 247, 195, 15, 183, 236,
                           219, 104, 212, 75, 211)

        self.assertEqual(output_expected, output)

    def test_empty(self):
        with self.assertRaises(TypeError):
            UInt256ToString(None)
        with self.assertRaises(ValueError):
            UInt256ToString(b'')
