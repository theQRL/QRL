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
        self.assertEqual('0002d27d73162f36e6e839eeaf829e6842c124144a3b067d4583778b2f152362400dd3a66701',
                         bin2hstr(address))
