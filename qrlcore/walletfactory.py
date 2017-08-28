import time

from twisted.internet.protocol import ServerFactory

from qrlcore.walletprotocol import WalletProtocol


class WalletFactory(ServerFactory):
    def __init__(self, stuff, chain, state, p2pFactory):
        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.protocol = WalletProtocol
        self.newaddress = 0
        self.stuff = stuff
        self.recn = 0
        self.maxconnections = 1
        self.connections = 0
        self.start_time = time.time()
        self.last_cmd = 'help'
