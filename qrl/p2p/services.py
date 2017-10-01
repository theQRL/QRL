from concurrent.futures import ThreadPoolExecutor

import grpc

from qrl.core import logger
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2 import PingReq, PongResp, GetKnownPeersReq, GetKnownPeersResp
from qrl.generated.qrl_pb2_grpc import P2PNodeServicer, add_P2PNodeServicer_to_server, PublicAPIServicer, \
    add_PublicAPIServicer_to_server
from qrl.p2p.node import QRLNode


class P2PService(P2PNodeServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, node: QRLNode):
        self.node = node

    def Ping(self, request: PingReq, context: object) -> PongResp:
        logger.debug("Ping!")
        return PongResp(message='Hello, %s!' % request.name)

    def GetKnownPeers(self, request: GetKnownPeersReq, context) -> GetKnownPeersResp:
        logger.debug("[QRLNode] GetPeers")

        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.node.peer_addresses])

        return GetKnownPeersResp(known_peers=known_peers)


class APIService(PublicAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, node: QRLNode):
        self.node = node

    def GetKnownPeers(self, request: GetKnownPeersReq, context) -> GetKnownPeersResp:
        logger.debug("[QRLNode] GetPeers")

        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.node.peer_addresses])

        return GetKnownPeersResp(known_peers=known_peers)


def start_services(node: QRLNode):

    server = grpc.server(ThreadPoolExecutor(max_workers=10))

    add_P2PNodeServicer_to_server(P2PService(node), server)
    add_PublicAPIServicer_to_server(APIService(node), server)

    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("grpc node - started !")

    return server
