# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from concurrent.futures import ThreadPoolExecutor

import grpc

from qrl.core import logger, config
from qrl.core.qrlnode import QRLNode
from qrl.generated.qrl_pb2_grpc import add_P2PAPIServicer_to_server, add_PublicAPIServicer_to_server
from qrl.generated.qrlbase_pb2_grpc import add_BaseServicer_to_server
from qrl.services.BaseService import BaseService
from qrl.services.P2PNode import P2PNode
from qrl.services.PublicAPIService import PublicAPIService


def start_services(node: QRLNode):
    server = grpc.server(ThreadPoolExecutor(max_workers=1),
                         maximum_concurrent_rpcs=config.user.max_peers_limit)
    p2p_node = P2PNode(node)

    add_BaseServicer_to_server(BaseService(node), server)
    add_P2PAPIServicer_to_server(p2p_node.service, server)
    add_PublicAPIServicer_to_server(PublicAPIService(node), server)

    server.add_insecure_port("[::]:9009")
    server.start()
    logger.debug("grpc node - started !")

    return server, p2p_node
