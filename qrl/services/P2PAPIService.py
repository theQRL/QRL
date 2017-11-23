# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Callable  # noqa

from grpc import StatusCode

from qrl.core import logger
from qrl.core.Block import Block
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import P2PAPIServicer
from qrl.services.grpcHelper import grpc_exception_wrapper


class P2PAPIService(P2PAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, node: QRLNode):
        self.qrlnode = node
        self.context_observer = None        # type: Callable

    @grpc_exception_wrapper(qrl_pb2.GetNodeStateResp, StatusCode.UNKNOWN)
    def GetNodeState(self, request: qrl_pb2.GetNodeStateReq, context) -> qrl_pb2.GetNodeStateResp:
        if self.context_observer is not None:
            self.context_observer(context)
        logger.debug("[GetNodeState]")
        return qrl_pb2.GetNodeStateResp(info=self.qrlnode.getNodeInfo())

    @grpc_exception_wrapper(qrl_pb2.GetKnownPeersResp, StatusCode.UNKNOWN)
    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        if self.context_observer is not None:
            self.context_observer(context)
        response = qrl_pb2.GetKnownPeersResp()
        response.node_info.CopyFrom(self.qrlnode.getNodeInfo())
        response.known_peers.extend([qrl_pb2.Peer(ip=p) for p in self.qrlnode._peer_addresses])
        return response

    @grpc_exception_wrapper(qrl_pb2.GetBlockResp, StatusCode.UNKNOWN)
    def GetBlock(self, request: qrl_pb2.GetBlockReq, context) -> qrl_pb2.GetBlockResp:
        response = qrl_pb2.GetBlockResp()
        response.node_info.CopyFrom(self.qrlnode.getNodeInfo())

        if request.HasField("index"):
            block = self.qrlnode.get_block_from_index(request.index)
            if isinstance(block, Block):
                response.block.CopyFrom(block.pbdata)
        else:
            raise NotImplementedError()

        return response
