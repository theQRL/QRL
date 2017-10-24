# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from grpc import StatusCode

from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import P2PNodeServicer
from qrl.services.grpcHelper import grpc_exception_wrapper


class P2PNodeService(P2PNodeServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, node: QRLNode):
        self.node = node

    @grpc_exception_wrapper(qrl_pb2.PongResp, StatusCode.UNKNOWN)
    def Ping(self, request: qrl_pb2.PingReq, context: object) -> qrl_pb2.PongResp:
        return qrl_pb2.PongResp(message='Hello, %s!' % request.name)

    @grpc_exception_wrapper(qrl_pb2.GetKnownPeersResp, StatusCode.UNKNOWN)
    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.node._peer_addresses])
        return qrl_pb2.GetKnownPeersResp(known_peers=known_peers)

    @grpc_exception_wrapper(qrl_pb2.GetInfoResp, StatusCode.UNKNOWN)
    def GetInfo(self, request: qrl_pb2.GetInfoReq, context) -> qrl_pb2.GetInfoResp:
        response = qrl_pb2.GetInfoResp()
        response.node_info.CopyFrom(self.node.getNodeInfo())
        response.known_peers.extend([qrl_pb2.Peer(ip=p) for p in self.node._peer_addresses])
        return response
