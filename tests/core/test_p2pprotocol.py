# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from google.protobuf.json_format import MessageToJson
from mock import Mock, MagicMock
from pyqrllib.pyqrllib import bin2hstr, hstr2bin

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
        p.factory.height = 0

        tmp_peer = Mock()
        p.transport.getPeer = MagicMock(return_value=tmp_peer)

        data = qrl_pb2.BlockMetaData()
        data.block_number = 3
        data.hash_header = bytes(hstr2bin('3582a839b7d778b2d11ec2dfdd3a487c3e946e5113bd1bf3da57d9cbc6615413'))

        jsonData = MessageToJson(data)
        p.CB(jsonData)
