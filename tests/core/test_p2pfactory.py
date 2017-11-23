# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.p2pfactory import P2PFactory
from qrl.core.p2pprotocol import P2PProtocol

logger.initialize_default(force_console_output=True)


class TestP2PFactory(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PFactory, self).__init__(*args, **kwargs)

    def test_create_factory(self):
        factory = P2PFactory(buffered_chain=None, sync_state=None, qrl_node=None)
        self.assertEqual(factory.protocol, P2PProtocol,
                         "Factory has not been assigned the expected protocol")
