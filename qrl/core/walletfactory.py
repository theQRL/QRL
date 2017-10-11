# coding=utf-8
import time

from twisted.internet.protocol import ServerFactory

from qrl.core.walletprotocol import WalletProtocol


class WalletFactory(ServerFactory):
    def __init__(self, stuff, chain, state, p2pFactory, api_factory, qrlnode):
        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.apiFactory = api_factory
        self.qrlnode = qrlnode
        self.protocol = WalletProtocol
        self.newaddress = 0

        # FIXME: stuff is not a very descriptive name..
        self.stuff = stuff
        self.recn = 0
        self.maxconnections = 1
        self.connections = 0
        self.start_time = time.time()
        self.last_cmd = 'help'
