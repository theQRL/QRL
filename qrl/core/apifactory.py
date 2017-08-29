from twisted.internet.protocol import ServerFactory

from apiprotocol import ApiProtocol


class ApiFactory(ServerFactory):
    def __init__(self, pos, chain, state, peers):
        self.protocol = ApiProtocol
        self.connections = 0
        self.api = 1
        self.pos = pos
        self.chain = chain
        self.state = state
        self.peers = peers

    # def buildProtocol(self, addr):
    #     self.protocol = ApiProtocol()
    #     self.protocol.factory = self
    #     return self.protocol
