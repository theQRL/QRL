# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from concurrent.futures import ThreadPoolExecutor

import grpc

from qrl.core import logger
from qrl.core.qrlnode import QRLNode
from qrl.generated.qrl_pb2_grpc import add_P2PNodeServicer_to_server, add_PublicAPIServicer_to_server
from qrl.generated.qrlbase_pb2_grpc import add_BaseServicer_to_server
from qrl.services.BaseService import BaseService
from qrl.services.P2PNodeService import P2PNodeService
from qrl.services.PublicAPIService import PublicAPIService


def start_services(node: QRLNode):
    server = grpc.server(ThreadPoolExecutor(max_workers=1))

    add_BaseServicer_to_server(BaseService(node), server)
    add_P2PNodeServicer_to_server(P2PNodeService(node), server)
    add_PublicAPIServicer_to_server(PublicAPIService(node), server)

    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("grpc node - started !")

    return server
