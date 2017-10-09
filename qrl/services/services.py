from concurrent.futures import ThreadPoolExecutor

import grpc

from qrl.core import logger
from qrl.generated.qrl_pb2_grpc import add_P2PNodeServicer_to_server, add_PublicAPIServicer_to_server
from qrl.services.APIService import APIService
from qrl.services.P2PService import P2PService
from qrl.services.node import QRLNode


def start_services(node: QRLNode):
    server = grpc.server(ThreadPoolExecutor(max_workers=10))

    add_P2PNodeServicer_to_server(P2PService(node), server)
    add_PublicAPIServicer_to_server(APIService(node), server)

    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("grpc node - started !")

    return server
