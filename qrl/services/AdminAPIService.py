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

    @grpc_exception_wrapper(qrl_pb2.GetLocalAddressesResp, StatusCode.UNKNOWN)
    def GetLocalAddresses(self, request: qrl_pb2.GetLocalAddressesReq, context) -> qrl_pb2.GetLocalAddressesResp:
        return qrl_pb2.GetLocalAddressesResp(addresses=self.qrlnode.addresses)

    @grpc_exception_wrapper(qrl_pb2.GetWalletResp, StatusCode.UNKNOWN)
    def GetWallet(self, request: qrl_pb2.GetWalletReq, context) -> qrl_pb2.GetWalletResp:
        answer = qrl_pb2.GetWalletResp()

        addr_bundle = self.qrlnode.get_address_bundle(request.address)
        if addr_bundle is not None:
            answer.wallet.CopyFrom(qrl_pb2.Wallet(address=addr_bundle.address,
                                                  mnemonic=addr_bundle.xmss.get_mnemonic(),
                                                  xmss_index=addr_bundle.xmss.get_index()))

        return answer
