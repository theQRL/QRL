# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
import logging

from twisted.internet import reactor

from qrl.core.BufferedChain import BufferedChain
from qrl.core.qrlnode import QRLNode
from qrl.services.services import start_services
from .core import logger, ntp, config
from .core.Chain import Chain
from .core.node import SyncState, POS
from .core.p2pfactory import P2PFactory
from .core.State import State
from qrl.core import logger_twisted

LOG_FORMAT_CUSTOM = '%(asctime)s|%(version)s|%(node_state)s| %(levelname)s : %(message)s'


class ContextFilter(logging.Filter):
    def __init__(self, node_state, version):
        super(ContextFilter, self).__init__()
        self.node_state = node_state
        self.version = version

    def filter(self, record):
        record.node_state = self.node_state.state.name
        record.version = self.version
        return True


def parse_arguments():
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

    return parser.parse_args()


def set_logger(args, sync_state):
    log_level = logging.INFO
    if args.logLevel:
        log_level = getattr(logging, args.logLevel)
    logger.initialize_default(force_console_output=not args.quiet).setLevel(log_level)
    custom_filter = ContextFilter(sync_state, config.dev.version)
    logger.logger.addFilter(custom_filter)
    file_handler = logger.log_to_file()
    file_handler.addFilter(custom_filter)
    file_handler.setLevel(logging.DEBUG)
    logger.set_colors(not args.no_colors, LOG_FORMAT_CUSTOM)
    logger.set_unhandled_exception_handler()
    logger_twisted.enable_twisted_log_observer()


def start_legacy_services(buffered_chain: BufferedChain,
                          qrlnode: QRLNode,
                          sync_state: SyncState):
    # NOTE: These services are obsolete and will be removed soon
    # FIXME: Again, we have cross-references between node, factory, chain and node_state

    p2p_factory = P2PFactory(buffered_chain=buffered_chain, sync_state=sync_state, qrl_node=qrlnode)
    pos = POS(buffered_chain=buffered_chain, p2p_factory=p2p_factory, sync_state=sync_state, time_provider=ntp)

    qrlnode.set_p2pfactory(p2p_factory)

    reactor.listenTCP(9000, p2p_factory)
    p2p_factory.connect_peers()

    pos.restart_monitor_bk(80)
    reactor.callLater(20, pos.unsynced_logic)

    reactor.run()


def main():
    args = parse_arguments()

    logger.debug("=====================================================================================")
    logger.info("Data Path: %s", args.data_path)
    logger.info("Wallet Path: %s", args.wallet_path)

    config.user.data_path = args.data_path
    config.user.wallet_path = args.wallet_path
    config.create_path(config.user.data_path)
    config.create_path(config.user.wallet_path)

    sync_state = SyncState()

    set_logger(args, sync_state)

    ntp.setDrift()

    logger.info('Initializing chain..')
    persistent_state = State()
    buffered_chain = BufferedChain(Chain(state=persistent_state))

    qrlnode = QRLNode(db_state=persistent_state)
    qrlnode.set_chain(buffered_chain)

    logger.info('QRL blockchain ledger %s', config.dev.version)
    logger.info('mining/staking address %s', buffered_chain.staking_address)

    if args.get_wallets:
        tmp = qrlnode.addresses
        if len(tmp) > 0:
            print(tmp[0].decode())
        return

    #######
    # NOTE: Keep assigned to a variable or might get collected
    grpc_service, p2p_node = start_services(qrlnode)

    buffered_chain.load()

    start_legacy_services(buffered_chain, qrlnode, sync_state)
