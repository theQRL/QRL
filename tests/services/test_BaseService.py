# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import os
from mock import Mock

from qrl.core import logger, config
from qrl.core.State import State
from qrl.core.qrlnode import QRLNode
from qrl.generated.qrlbase_pb2 import GetNodeInfoReq
from qrl.services.BaseService import BaseService

logger.initialize_default(force_console_output=True)


class TestBaseAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBaseAPI, self).__init__(*args, **kwargs)

    def test_getNodeInfo(self):
        db_state = Mock(spec=State)
        qrlnode = QRLNode(db_state)

        service = BaseService(qrlnode)
        response = service.GetNodeInfo(request=GetNodeInfoReq, context=None)

        self.assertEqual(config.dev.version, response.version)

        proto_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                  os.path.pardir,
                                                  os.path.pardir,
                                                  "qrl", "protos", "qrl.proto"))

        with open(proto_path, 'r') as content_file:
            proto_content = content_file.read()

        self.assertEqual(proto_content, response.grpcProto)
