# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
import logging

from twisted.internet import reactor

from qrl.core.qrlnode import QRLNode
from qrl.services.services import start_services
from . import webwallet
from .core import logger, ntp, config
from .core.apifactory import ApiFactory
from .core.chain import Chain
from .core.node import NodeState, POS
from .core.p2pfactory import P2PFactory
from .core.state import State
from .core.walletfactory import WalletFactory
from qrl.core import logger_twisted

LOG_FORMAT_CUSTOM = '%(asctime)s |%(node_state)s| %(levelname)s : %(message)s'


class ContextFilter(logging.Filter):
    def __init__(self, node_state):
        super(ContextFilter, self).__init__()
        self.node_state = node_state

    def filter(self, record):
        record.node_state = self.node_state.state.name
        return True


def main():
    parser = argparse.ArgumentParser(description='QRL node')
    parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', required=False, default=False,
                        help="Avoid writing data to the console")
    parser.add_argument('--datapath', '-d', dest='data_path', default=config.user.data_path,
                        help="Retrieve data from a different path")
    parser.add_argument('--walletpath', '-w', dest='wallet_path', default=config.user.wallet_path,
                        help="Retrieve wallet from a different path")
    parser.add_argument('--no-colors', dest='no_colors', action='store_true', default=False,
                        help="Disables color output")
    parser.add_argument("-l", "--loglevel", dest="logLevel", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")
    parser.add_argument("--get-wallets", dest="get_wallets", action='store_true', default=False,
                        help="Returns wallet address and stops the node")

    args = parser.parse_args()

    logger.debug("=====================================================================================")

    logger.info("Data Path: %s", args.data_path)
    logger.info("Wallet Path: %s", args.wallet_path)
    config.user.data_path = args.data_path
    config.user.wallet_path = args.wallet_path
    config.create_path(config.user.data_path)
    config.create_path(config.user.wallet_path)

    node_state = NodeState()

    # Logging configuration
    log_level = logging.INFO
    if args.logLevel:
        log_level = getattr(logging, args.logLevel)

    logger.initialize_default(force_console_output=not args.quiet).setLevel(log_level)

    custom_filter = ContextFilter(node_state)
    logger.logger.addFilter(custom_filter)
    file_handler = logger.log_to_file()
    file_handler.addFilter(custom_filter)
    file_handler.setLevel(logging.DEBUG)

    logger.set_colors(not args.no_colors, LOG_FORMAT_CUSTOM)
    logger.set_unhandled_exception_handler()
    logger_twisted.enable_twisted_log_observer()

    ntp.setDrift()

    logger.info('Initializing chain..')
    state_obj = State()
    chain_obj = Chain(state=state_obj)

    qrlnode = QRLNode(db_state=state_obj)
    qrlnode.set_chain(chain_obj)

    logger.info('QRL blockchain ledger %s', config.dev.version)
    logger.info('mining/staking address %s', chain_obj.mining_address)

    if args.get_wallets:
        address_data = chain_obj.wallet.list_addresses(chain_obj.state,
                                                       chain_obj.transaction_pool)
        addresses = [a[0] for a in address_data]
        print((addresses[0]))
        return

    #######
    # NOTE: Keep assigned to a variable or it will be collected
    qrlserver = start_services(qrlnode)
    #######


    logger.info('Reading chain..')
    chain_obj.m_load_chain()
    logger.info(str(len(chain_obj.m_blockchain)) + ' blocks')
    logger.info('Verifying chain')
    logger.info('Building state leveldb')


    # FIXME: Again, we have cross-references between node, factory, chain and node_state
    p2p_factory = P2PFactory(chain=chain_obj, nodeState=node_state, node=qrlnode)
    pos = POS(chain=chain_obj, p2pFactory=p2p_factory, nodeState=node_state, ntp=ntp)
    p2p_factory.setPOS(pos)

    qrlnode.set_p2pfactory(p2p_factory)


    # FIXME: Again, we have cross-references between node, factory, chain and node_state
    api_factory = ApiFactory(pos, chain_obj, state_obj, p2p_factory.peer_connections)

    welcome = 'QRL node connection established. Try starting with "help"\r\n'

    # FIXME: Again, we have cross-references between node, factory, chain and node_state
    wallet_factory = WalletFactory(welcome, chain_obj, state_obj, p2p_factory, api_factory, qrlnode)

    logger.info('>>>Listening..')
    reactor.listenTCP(2000, wallet_factory, interface='127.0.0.1')
    reactor.listenTCP(9000, p2p_factory)
    reactor.listenTCP(8080, api_factory)

    webwallet.WebWallet(chain_obj, state_obj, p2p_factory, qrlnode)

    pos.restart_monitor_bk(80)

    logger.info('Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"')

    p2p_factory.connect_peers()
    reactor.callLater(20, pos.unsynced_logic)

    reactor.run()
