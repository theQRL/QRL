from time import sleep

from qrl.core.qrlnode import QRLNode
from qrl.services.PeerPool import PeerPool


class P2PNodeClient(object):
    def __init__(self, node: QRLNode):
        self.node = node
        self.peer_pool = PeerPool()
        self.peer_pool.add(self.node.peer_addresses)

        sleep(50)