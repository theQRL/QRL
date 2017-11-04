# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from google.protobuf.json_format import MessageToJson
from mock import Mock, MagicMock

from qrl.core import logger
from qrl.core.Chain import Chain
from qrl.core.p2pprotocol import P2PProtocol
from qrl.generated import qrl_pb2

logger.initialize_default(force_console_output=True)


# FIXME: These tests will soon be removed
class TestP2PProtocol(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PProtocol, self).__init__(*args, **kwargs)

    def test_CB(self):
        p = P2PProtocol()
        p.transport = Mock()
        p.factory = Mock()

        p.factory.peers_blockheight = MagicMock(return_value=dict())
        p.factory.chain = Mock(spec=Chain)
        p.factory.chain.blockheight = MagicMock(return_value=0)

        tmp_peer = Mock()
        p.transport.getPeer = MagicMock(return_value=tmp_peer)

        data = qrl_pb2.BlockMetaData()
        data.block_number = 3
        data.hash_header = bytes((53, 130, 168, 57, 183, 215, 120, 178, 209, 30, 194, 223, 221, 58, 72, 124, 62, 148,
                                  110, 81, 19, 189, 27, 243, 218, 87, 217, 203, 198, 97, 84, 19))

        jsonData = MessageToJson(data)
        p.CB(jsonData)
