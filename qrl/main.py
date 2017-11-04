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
from .core.apifactory import ApiFactory
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

    sync_state = SyncState()

    # Logging configuration
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

    ntp.setDrift()

    logger.info('Initializing chain..')
    persistent_state = State()
    buffered_chain = BufferedChain(Chain(state=persistent_state))

    qrlnode = QRLNode(db_state=persistent_state)
    qrlnode.set_chain(buffered_chain)

    logger.info('QRL blockchain ledger %s', config.dev.version)
    logger.info('mining/staking address %s', buffered_chain.staking_address)

    if args.get_wallets:
        address_data = buffered_chain.wallet.list_addresses(persistent_state,
                                                            buffered_chain._chain.tx_pool.transaction_pool)
        addresses = [a[0] for a in address_data]
        print((addresses[0]))
        return

    #######
    # NOTE: Keep assigned to a variable or it will be collected
    grpc_service, p2p_node = start_services(qrlnode)
    #######

    logger.info('Reading chain..')
    buffered_chain.load()
    logger.info('{} blocks'.format(buffered_chain.length))
    logger.info('Verifying chain')
    logger.info('Building state leveldb')

    # FIXME: Again, we have cross-references between node, factory, chain and node_state
    p2p_factory = P2PFactory(buffered_chain=buffered_chain, sync_state=sync_state, node=qrlnode)
    pos = POS(buffered_chain=buffered_chain, p2pFactory=p2p_factory, sync_state=sync_state, time_provider=ntp)
    p2p_factory.setPOS(pos)

    qrlnode.set_p2pfactory(p2p_factory)

    # FIXME: Again, we have cross-references between node, factory, chain and node_state
    api_factory = ApiFactory(pos, buffered_chain, persistent_state, p2p_factory.peer_connections)

    logger.info('>>>Listening..')
    reactor.listenTCP(9000, p2p_factory)
    reactor.listenTCP(8080, api_factory)

    pos.restart_monitor_bk(80)

    logger.info('Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"')

    p2p_factory.connect_peers()
    reactor.callLater(20, pos.unsynced_logic)

    reactor.run()
