from time import sleep

from grpc import StatusCode

from qrl.core.qrlnode import QRLNode
from qrl.services.P2PNodeService import P2PNodeService
from qrl.services.PeerManager import PeerManager


class P2PNode(object):
    def __init__(self, node: QRLNode):
        self.service = P2PNodeService(node)
        self.service.context_observer = self.service_context_observer
        self.node = node
        self.peer_manager = PeerManager(self.node)
        self.peer_manager.add(self.node.peer_addresses)

    def service_context_observer(self, context):
        peer = context.peer()
        addr = peer.split(':')
        if len(addr) >= 3:
            self.peer_manager.add([addr[1]])
