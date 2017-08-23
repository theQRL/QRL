#!/usr/bin/env python

# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
from os.path import expanduser
import logging
from traceback import extract_tb

from twisted.internet import reactor

import qrlcore.apifactory
import qrlcore.p2pfactory
import qrlcore.walletfactory
import webwallet
# TODO: Clean this up
from qrlcore import apiprotocol, ntp, walletprotocol, node, logger
from qrlcore import configuration as config
from qrlcore.chain import Chain
from qrlcore.node import NodeState
# Initializing function to log console output
from qrlcore.state import State


def log_traceback(exctype, value, tb):  # Function to log error's traceback
    logger.error('*** Error ***')
    logger.error(str(exctype))
    logger.error(str(value))
    tb_info = extract_tb(tb)
    for line in tb_info:
        logger.info(line)


# sys.excepthook = log_traceback

LOG_FORMAT_CUSTOM = '%(asctime)s |%(node_state)s| - %(levelname)s  - %(message)s'

class ContextFilter(logging.Filter):
    def __init__(self, node_state):
        super(ContextFilter, self).__init__()
        self.node_state = node_state

    def filter(self, record):
        record.node_state = self.node_state.state
        return True


def main():
    parser = argparse.ArgumentParser(description='QRL node')
    parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', required=False, default=False)
    parser.add_argument('--datapath', '-d', dest='data_path', default=expanduser("~/.qrl"))
    args = parser.parse_args()

    logger.initialize_default(force_console_output=not args.quiet)
    logger.log_to_file()

    logger.info("Data Path: %s", args.data_path)
    config.user.data_path = args.data_path

    nodeState = NodeState()
    custom_filter = ContextFilter(nodeState)
    for h in logger.logger.handlers:
        h.setFormatter(logging.Formatter(LOG_FORMAT_CUSTOM))
    logger.logger.addFilter(custom_filter)

    ntp.setDrift()

    logger.info('Initializing chain..')
    stateObj = State()
    chainObj = Chain(state=stateObj)

    logger.info('Reading chain..')
    chainObj.m_load_chain()
    logger.info(str(len(chainObj.m_blockchain)) + ' blocks')
    logger.info('Verifying chain')
    logger.info('Building state leveldb')

    welcome = 'QRL node connection established. Try starting with "help"' + '\r\n'
    logger.info('>>>Listening..')

    p2pFactory = qrlcore.p2pfactory.P2PFactory(chain=chainObj, nodeState=nodeState)
    pos = node.POS(chain=chainObj, p2pFactory=p2pFactory, nodeState=nodeState, ntp=ntp)
    p2pFactory.setPOS(pos)

    apiFactory = apiprotocol.ApiFactory(pos, chainObj, stateObj, p2pFactory.peer_connections)
    walletFactory = walletprotocol.WalletFactory(welcome, chainObj, stateObj, p2pFactory)

    logger.info('Reading chain..')
    reactor.listenTCP(2000, walletFactory, interface='127.0.0.1')
    reactor.listenTCP(9000, p2pFactory)
    reactor.listenTCP(8080, apiFactory)

    # Load web wallet HERE??
    webwallet.WebWallet(chainObj, stateObj, p2pFactory)

    pos.restart_monitor_bk(80)

    logger.info('Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"')
    logger.info('<<<Connecting to nodes in peer.dat')

    p2pFactory.connect_peers()
    reactor.callLater(20, pos.unsynced_logic)

    reactor.run()

if __name__ == "__main__":
    main()
