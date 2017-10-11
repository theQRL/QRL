# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from concurrent.futures import ThreadPoolExecutor

import grpc
from grpc_reflection.v1alpha.reflection import enable_server_reflection

from qrl.core import logger
from qrl.core.qrlnode import QRLNode
from qrl.generated.qrl_pb2_grpc import add_P2PNodeServicer_to_server, add_PublicAPIServicer_to_server
from qrl.services.APIService import APIService
from qrl.services.P2PService import P2PService


def start_services(node: QRLNode):
    server = grpc.server(ThreadPoolExecutor(max_workers=1))

    add_P2PNodeServicer_to_server(P2PService(node), server)
    add_PublicAPIServicer_to_server(APIService(node), server)

    services = ['qrl.PublicAPI']

    enable_server_reflection(services, server)

    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("grpc node - started !")

    return server
