# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# FIXME: This is odd...
from grpc import StatusCode

from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import AdminAPIServicer
from qrl.services.grpcHelper import grpc_exception_wrapper


class AdminAPIService(AdminAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode
