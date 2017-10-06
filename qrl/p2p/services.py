from concurrent.futures import ThreadPoolExecutor

import grpc
from google.protobuf.message import Error

from qrl.core import logger
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import P2PNodeServicer, add_P2PNodeServicer_to_server, PublicAPIServicer, \
    add_PublicAPIServicer_to_server
from qrl.p2p.node import QRLNode


class P2PService(P2PNodeServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, node: QRLNode):
        self.node = node

    def Ping(self, request: qrl_pb2.PingReq, context: object) -> qrl_pb2.PongResp:
        logger.debug("Ping!")
        return qrl_pb2.PongResp(message='Hello, %s!' % request.name)

    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        logger.debug("[QRLNode] GetPeers")

        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.node.peer_addresses])

        return qrl_pb2.GetKnownPeersResp(known_peers=known_peers)


class APIService(PublicAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, node: QRLNode):
        self.node = node

    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        logger.debug("[QRLNode] GetPeers")

        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.node.peer_addresses])

        return qrl_pb2.GetKnownPeersResp(known_peers=known_peers)

    def GetAddressState(self, request: qrl_pb2.GetAddressStateReq, context) -> qrl_pb2.GetAddressStateResp:
        logger.debug("[QRLNode] GetAddressState")

        try:
            address_state = self.node.get_address_state(request.address)
        except Exception as e:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(e)
            return None

        return qrl_pb2.GetAddressStateResp(state=address_state)

    def TransferCoins(self, request: qrl_pb2.TransferCoinsReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[QRLNode] TransferCoins")
        return qrl_pb2.TransferCoinsResp()


def start_services(node: QRLNode):
    server = grpc.server(ThreadPoolExecutor(max_workers=10))

    add_P2PNodeServicer_to_server(P2PService(node), server)
    add_PublicAPIServicer_to_server(APIService(node), server)

    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("grpc node - started !")

    return server
