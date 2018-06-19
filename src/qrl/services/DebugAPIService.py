# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core import config
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrldebug_pb2
from qrl.generated.qrldebug_pb2_grpc import DebugAPIServicer
from qrl.services.grpcHelper import GrpcExceptionWrapper


class DebugAPIService(DebugAPIServicer):
    MAX_REQUEST_QUANTITY = 100

    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    @GrpcExceptionWrapper(qrldebug_pb2.GetFullStateResp)
    def GetFullState(self, request: qrldebug_pb2.GetFullStateReq, context) -> qrldebug_pb2.GetFullStateResp:
        return qrldebug_pb2.GetFullStateResp(
            coinbase_state=self.qrlnode.get_address_state(config.dev.coinbase_address).pbdata,
            addresses_state=self.qrlnode.get_all_address_state()
        )
