import threading
from time import sleep

from qrl.core import logger
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.services.P2PNodeService import P2PNodeService
from qrl.services.PeerManager import PeerManager


class BlockChainManager(object):
    def __init__(self, node, peer_manager):
        self.node = node
        self.peer_manager = peer_manager

        self.thread = threading.Thread(target=self._synchronize_chain)
        self.thread.daemon = True
        self.thread.start()

    def _block_received(self, response_future):
        logger.info("[{:20}] _block_received".format(response_future.pm.conn_addr))

    def _synchronize_chain(self):
        while True:
            logger.info("Peers  {:4} ({:4})".format(self.peer_manager.stable_peer_count, self.peer_manager.peer_count))
            for peer_metadata in self.peer_manager.stable_peers():
                logger.info("{:20}: {:3}".format(peer_metadata.conn_addr,
                                                 peer_metadata.node_info.block_height))

            for peer_metadata in self.peer_manager.stable_peers():
                req = qrl_pb2.GetBlockReq()
                req.index = 1
                f = peer_metadata.stub.GetBlock.future(req, timeout=PeerManager.TIMEOUT_SECS)
                f.pm = peer_metadata
                f.add_done_callback(self._block_received)

            sleep(2)


class P2PNode(object):
    def __init__(self, node: QRLNode):
        self.service = P2PNodeService(node)
        self.service.context_observer = self.service_context_observer
        self.node = node
        self.peer_manager = PeerManager(self.node)
        self.peer_manager.add(self.node.peer_addresses)
        self.blockchain_manager = BlockChainManager(self.node, self.peer_manager)

    def service_context_observer(self, context):
        peer = context.peer()
        addr = peer.split(':')
        if len(addr) >= 3:
            self.peer_manager.add([addr[1]])
