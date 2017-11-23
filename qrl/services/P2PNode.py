from qrl.core.qrlnode import QRLNode
from qrl.services.P2PAPIService import P2PAPIService


class P2PNode(object):
    def __init__(self, node: QRLNode):
        self.service = P2PAPIService(node)
        self.node = node

        self.peer_manager = None
        # FIXME: Disabled for the moment

        # self.peer_manager = PeerManager(self.node)
        # self.peer_manager.add(self.node.peer_addresses)
        # self.service.context_observer = self.service_context_observer
        # self.blockchain_manager = BlockChainManager(self.node, self.peer_manager)

    def service_context_observer(self, context):
        peer = context.peer()
        addr = peer.split(':')
        if len(addr) >= 3:
            self.peer_manager.add([addr[1]])
