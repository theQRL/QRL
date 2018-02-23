# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import bin2hstr

from qrl.core.misc import logger
from tests.misc import helper

logger.initialize_default()


class TestHelpers(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHelpers, self).__init__(*args, **kwargs)

    def test_getAddress(self):
        address = helper.qrladdress('mySeed')
        self.assertEqual('00020080a24d25a75c99077719c6b5077b0ae16cf243f69d142e848075e985dbb28df7fbcd5acf',
                         bin2hstr(address))
