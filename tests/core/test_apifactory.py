# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.apifactory import ApiFactory
from qrl.core.apiprotocol import ApiProtocol

logger.initialize_default(force_console_output=True)


class TestAPIFactory(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestAPIFactory, self).__init__(*args, **kwargs)

    def test_create_factory(self):
        factory = ApiFactory(pos=None, chain=None, state=None, peers=None)
        self.assertEqual(factory.protocol, ApiProtocol,
                         "Factory has not been assigned the expected protocol")
        self.assertEqual(factory.api, 1)
        self.assertEqual(factory.connections, 0)
