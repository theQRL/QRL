# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from concurrent.futures import ThreadPoolExecutor

import grpc

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.qrlnode import QRLNode
from qrl.generated.qrl_pb2_grpc import add_PublicAPIServicer_to_server, add_AdminAPIServicer_to_server
from qrl.generated.qrlbase_pb2_grpc import add_BaseServicer_to_server
from qrl.services.AdminAPIService import AdminAPIService
from qrl.services.BaseService import BaseService
from qrl.services.PublicAPIService import PublicAPIService


def start_services(node: QRLNode):
    public_server = grpc.server(ThreadPoolExecutor(max_workers=1),
                                maximum_concurrent_rpcs=config.user.max_peers_limit)
    add_BaseServicer_to_server(BaseService(node), public_server)
    add_PublicAPIServicer_to_server(PublicAPIService(node), public_server)

    public_server.add_insecure_port("[::]:9009")
    public_server.start()

    logger.info("grpc public service - started !")

    admin_server = grpc.server(ThreadPoolExecutor(max_workers=1),
                               maximum_concurrent_rpcs=config.user.max_peers_limit)
    add_AdminAPIServicer_to_server(AdminAPIService(node), admin_server)

    admin_server.add_insecure_port("127.0.0.1:9008")
    admin_server.start()

    logger.info("grpc admin service - started !")

    return admin_server, public_server
