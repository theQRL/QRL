from concurrent.futures import ThreadPoolExecutor

import grpc
import os

from qrl.core import logger, config
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2 import PingRequest, PongReply, GetKnownPeersRequest, GetKnownPeersReply
from qrl.generated.qrl_pb2_grpc import P2PNodeServicer, add_P2PNodeServicer_to_server


class QRLNode(P2PNodeServicer):
    # TODO: Separate the Service from the node model

    def Ping(self, request: PingRequest, context: object) -> PongReply:
        logger.debug("Ping!")
        return PongReply(message='Hello, %s!' % request.name)

    def GetKnownPeers(self, request: GetKnownPeersRequest, context) -> GetKnownPeersReply:
        logger.debug("GetPeers")

        peers_path = os.path.join(config.user.data_path, config.dev.peers_filename)

        known_peers = qrl_pb2.KnownPeers()
        if os.path.isfile(peers_path) is True:
            with open(peers_path, 'rb') as infile:
                known_peers.ParseFromString(infile.read())
        else:
            peer_list = config.user.peer_list
            known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in peer_list])

        return GetKnownPeersReply(known_peers=known_peers)


def start_node():
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    add_P2PNodeServicer_to_server(QRLNode(), server)
    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("P2P node - started !")
    return server
