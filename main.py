#!/usr/bin/env python

# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
from traceback import extract_tb
from twisted.internet import reactor

import webwallet

# TODO: Clean this up
from qrlcore import chain, block, apiprotocol, merkle, transaction, ntp, wallet, walletprotocol, state, helper, node, \
    fork, logger
from qrlcore.chain import Chain

from qrlcore.node import NodeState

# Initializing function to log console output
from qrlcore.state import State


def log_traceback(exctype, value, tb):  # Function to log error's traceback
    logger.info('*** Error ***')
    logger.info(str(exctype))
    logger.info(str(value))
    tb_info = extract_tb(tb)
    for line in tb_info:
        logger.info(tb_info)


# sys.excepthook = log_traceback

def main():
    parser = argparse.ArgumentParser(description='QRL node')
    parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', required=False, default=False)

    args = parser.parse_args()

    logger.initialize_default(force_console_output=not args.quiet)
    logger.log_to_file()

    nodeState = NodeState()     # FIXME: purpose?
    ntp.setDrift()

    stateObj = State()
    logger.info('Initializing chain..')
    chainObj = Chain(state=stateObj)

    logger.info('Reading chain..')
    chainObj.m_load_chain()
    logger.info(str(len(chainObj.m_blockchain)) + ' blocks')
    logger.info('Verifying chain')
    logger.info('Building state leveldb')

    logger.info('Loading node list..')  # load the peers for connection based upon previous history..
    chainObj.state.state_load_peers()
    logger.info(chainObj.state.state_get_peers())

    welcome = 'QRL node connection established. Try starting with "help"' + '\r\n'
    logger.info('>>>Listening..')

    p2pFactory = node.P2PFactory(chain=chainObj, nodeState=nodeState)
    pos = node.POS(chain=chainObj, p2pFactory=p2pFactory, nodeState=nodeState, ntp=ntp)
    p2pFactory.setPOS(pos)

    apiFactory = apiprotocol.ApiFactory(pos, chainObj, stateObj, p2pFactory.peers)
    walletFactory = walletprotocol.WalletFactory(welcome, chainObj, stateObj, p2pFactory)

    logger.info('Reading chain..')
    reactor.listenTCP(2000, walletFactory, interface='127.0.0.1')
    reactor.listenTCP(9000, p2pFactory)
    reactor.listenTCP(8080, apiFactory)

    # Load web wallet HERE??
    webWallet = webwallet.WebWallet(chainObj, stateObj, p2pFactory)

    pos.restart_monitor_bk(80)

    logger.info('Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"')
    logger.info('<<<Connecting to nodes in peer.dat')

    p2pFactory.connect_peers()
    reactor.callLater(20, pos.unsynced_logic)

    reactor.run()

if __name__ == "__main__":
    main()
