# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
import logging

from twisted.internet import reactor
from pyqrllib.pyqrllib import hstr2bin

from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.misc import ntp, logger, logger_twisted
from qrl.core.qrlnode import QRLNode
from qrl.services.services import start_services
from qrl.core import config
from qrl.core.State import State

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
    parser.add_argument('--mining_thread_count', '-m', dest='mining_thread_count', action='store_true', required=False,
                        default=config.user.mining_thread_count, help="Number of threads for mining")
    parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', required=False, default=False,
                        help="Avoid writing data to the console")
    parser.add_argument('--datadir', '-d', dest='data_dir', default=config.user.data_dir,
                        help="Retrieve data from a different path")
    parser.add_argument('--no-colors', dest='no_colors', action='store_true', default=False,
                        help="Disables color output")
    parser.add_argument("-l", "--loglevel", dest="logLevel", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")
    parser.add_argument('--miningCreditWallet', dest='mining_credit_wallet', required=True,
                        help="QRL Wallet address on which mining reward has to be credited.")
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


def get_mining_credit_wallet(mining_credit_wallet: str):
    try:
        mining_credit_wallet = bytes(hstr2bin(mining_credit_wallet[1:]))
        if AddressState.address_is_valid(mining_credit_wallet):
            return mining_credit_wallet
    except Exception:
        logger.info('Exception in validate_mining_credit_wallet')

    return None


def main():
    args = parse_arguments()

    config.create_path(config.user.wallet_dir)
    mining_credit_wallet = get_mining_credit_wallet(args.mining_credit_wallet)

    if not mining_credit_wallet:
        logger.warning('Invalid Mining Credit Wallet Address')
        logger.warning('%s', args.mining_credit_wallet)
        return False

    logger.debug("=====================================================================================")
    logger.info("Data Path: %s", args.data_dir)

    config.user.data_dir = args.data_dir
    config.create_path(config.user.data_dir)

    ntp.setDrift()

    logger.info('Initializing chain..')
    persistent_state = State()
    chain_manager = ChainManager(state=persistent_state)
    chain_manager.load(Block.from_json(GenesisBlock().to_json()))

    qrlnode = QRLNode(db_state=persistent_state, mining_credit_wallet=mining_credit_wallet)
    qrlnode.set_chain_manager(chain_manager)

    set_logger(args, qrlnode.sync_state)

    #######
    # NOTE: Keep assigned to a variable or might get collected
    admin_service, grpc_service, mining_service = start_services(qrlnode)

    qrlnode.start_listening()
    qrlnode.connect_peers()

    qrlnode.start_pow(args.mining_thread_count)

    logger.info('QRL blockchain ledger %s', config.dev.version)
    logger.info('mining/staking address %s', args.mining_credit_wallet)

    # FIXME: This will be removed once we move away from Twisted
    reactor.run()
