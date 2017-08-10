import state
import chain
import apiprotocol
import walletprotocol
import node
import block
import helper
import transaction
import wallet
import ntp
import logger
import fork
import merkle
import sys
from traceback import extract_tb
from twisted.internet import reactor


# Initializing function to log console output

def log_traceback(exctype, value, tb):  # Function to log error's traceback
    printL(('*** Error ***'))
    printL((str(exctype)))
    printL((str(value)))
    tb_info = extract_tb(tb)
    for line in tb_info:
        printL((tb_info))


# sys.excepthook = log_traceback


if __name__ == "__main__":
    nodeState = node.NodeState()

    log, consensus = logger.getLogger(__name__)
    printL = logger.PrintHelper(log, nodeState).printL
    ntp.printL = printL
    ntp.setDrift()

    node.printL = printL
    chain.printL = printL
    state.printL = printL
    walletprotocol.printL = printL
    apiprotocol.printL = printL
    wallet.printL = printL
    merkle.printL = printL
    fork.printL = printL
    ntp.printL = printL
    block.printL = printL
    helper.printL = printL
    transaction.printL = printL
    ntp.printL = printL
    fork.printL = printL

    stateObj = state.State()
    chainObj = chain.Chain(state=stateObj)

    printL(('Reading chain..'))
    chainObj.m_load_chain()
    printL((str(len(chainObj.m_blockchain)) + ' blocks'))
    printL(('Verifying chain'))
    printL(('Building state leveldb'))

    printL(('Loading node list..'))  # load the peers for connection based upon previous history..
    chainObj.state.state_load_peers()
    printL((chainObj.state.state_get_peers()))

    stuff = 'QRL node connection established. Try starting with "help"' + '\r\n'
    printL(('>>>Listening..'))

    p2pFactory = node.P2PFactory(chain=chainObj, nodeState=nodeState)
    pos = node.POS(chain=chainObj, p2pFactory=p2pFactory, nodeState=nodeState, ntp=ntp)
    p2pFactory.setPOS(pos)

    apiFactory = apiprotocol.ApiFactory(pos, chainObj, stateObj, p2pFactory.peers)

    stuff = 'QRL node connection established. Try starting with "help"' + '\r\n'
    walletFactory = walletprotocol.WalletFactory(stuff, chainObj, stateObj, p2pFactory)

    printL(('Reading chain..'))
    reactor.listenTCP(2000, walletFactory, interface='127.0.0.1')
    reactor.listenTCP(9000, p2pFactory)
    reactor.listenTCP(8080, apiFactory)

    pos.restart_monitor_bk(80)

    printL(('Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"'))
    printL(('<<<Connecting to nodes in peer.dat'))

    p2pFactory.connect_peers()
    reactor.callLater(20, pos.unsynced_logic)

    reactor.run()
