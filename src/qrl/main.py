# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
import faulthandler
import logging
import threading
from os.path import expanduser

from mock import MagicMock
from twisted.internet import reactor
from pyqrllib.pyqrllib import hstr2bin, bin2hstr

from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.misc import ntp, logger, logger_twisted
from qrl.core.qrlnode import QRLNode
from qrl.services.services import start_services
from qrl.core import config
from qrl.core.State import State

LOG_FORMAT_CUSTOM = '%(asctime)s|%(version)s|%(node_state)s|%(thread_id)s| %(levelname)s : %(message)s'


class ContextFilter(logging.Filter):
    def __init__(self, node_state, version):
        super(ContextFilter, self).__init__()
        self.node_state = node_state
        self.version = version

    def filter(self, record):
        record.node_state = "{:<8}".format(self.node_state.state.name)
        record.version = self.version
        record.thread_id = "{:<11}".format(threading.current_thread().name)
        return True


def parse_arguments():
    parser = argparse.ArgumentParser(description='QRL node')
    parser.add_argument('--mining_thread_count', '-m', dest='mining_thread_count', type=int, required=False,
                        default=config.user.mining_thread_count, help="Number of threads for mining")
    parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', required=False, default=False,
                        help="Avoid writing data to the console")
    parser.add_argument('--qrldir', '-d', dest='qrl_dir', default=config.user.qrl_dir,
                        help="Use a different directory for node data/configuration")
    parser.add_argument('--no-colors', dest='no_colors', action='store_true', default=False,
                        help="Disables color output")
    parser.add_argument("-l", "--loglevel", dest="logLevel", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")
    parser.add_argument('--miningAddress', dest='mining_address', required=False,
                        help="QRL Wallet address on which mining reward has to be credited.")
    parser.add_argument('--mockGetMeasurement', dest='measurement', required=False, type=int, default=-1,
                        help="Warning: Only for integration test, to mock get_measurement")
    parser.add_argument('--debug', dest='debug', action='store_true', default=False,
                        help="Enables fault handler")
    parser.add_argument('--mocknet', dest='mocknet', action='store_true', default=False,
                        help="Enables default mocknet settings")
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


def get_mining_address(mining_address: str):
    try:
        if not mining_address:
            mining_address = bytes(hstr2bin(config.user.mining_address[1:]))
        else:
            mining_address = bytes(hstr2bin(mining_address[1:]))

        if not AddressState.address_is_valid(mining_address):
            raise ValueError('Mining Address Validation Failed')

        return mining_address
    except Exception as e:
        logger.info('Failed Parsing Mining Address %s', e)

    return None


def main():
    args = parse_arguments()

    logger.debug("=====================================================================================")
    logger.info("QRL Path: %s", args.qrl_dir)
    config.user.qrl_dir = expanduser(args.qrl_dir)
    config.create_path(config.user.qrl_dir)
    logger.debug("=====================================================================================")

    config.create_path(config.user.wallet_dir)
    mining_address = None
    ntp.setDrift()

    logger.info('Initializing chain..')
    persistent_state = State()

    if args.mocknet:
        args.debug = True
        config.user.mining_enabled = True
        config.user.mining_thread_count = 1
        config.user.mining_pause = 500
        config.dev.mining_setpoint_blocktime = 1
        config.user.genesis_difficulty = 2

        # Mocknet mining address
        # Q01050058bb3f8cb66fd90d0347478e5bdf3a475e82cfc5fe5dc276500ca21531e6edaf3d2d0f7e
        # Mocknet mining hexseed
        # 010500dd70f898c2cb4c11ce7fd85aa04554e41dcc46569871d189a3f48d84e2fbedbe176695e291e9b81e619b3625c624cde6
        args.mining_address = 'Q01050058bb3f8cb66fd90d0347478e5bdf3a475e82cfc5fe5dc276500ca21531e6edaf3d2d0f7e'

    if args.debug:
        logger.warning("FAULT HANDLER ENABLED")
        faulthandler.enable()

    if config.user.mining_enabled:
        mining_address = get_mining_address(args.mining_address)

        if not mining_address:
            logger.warning('Invalid Mining Credit Wallet Address')
            logger.warning('%s', args.mining_address)
            return False

    if args.measurement > -1:
        persistent_state.get_measurement = MagicMock(return_value=args.measurement)

    chain_manager = ChainManager(state=persistent_state)
    chain_manager.load(Block.deserialize(GenesisBlock().serialize()))

    qrlnode = QRLNode(mining_address=mining_address)
    qrlnode.set_chain_manager(chain_manager)

    set_logger(args, qrlnode.sync_state)

    #######
    # NOTE: Keep assigned to a variable or might get collected
    admin_service, grpc_service, mining_service, debug_service = start_services(qrlnode)

    qrlnode.start_listening()
    qrlnode.connect_peers()

    qrlnode.start_pow(args.mining_thread_count)

    logger.info('QRL blockchain ledger %s', config.dev.version)
    if config.user.mining_enabled:
        logger.info('Mining/staking address %s using %s threads (0 = auto)', 'Q' + bin2hstr(mining_address), args.mining_thread_count)

    elif args.mining_address or args.mining_thread_count:
        logger.warning('Mining is not enabled but you sent some "mining related" param via CLI')

    # FIXME: This will be removed once we move away from Twisted
    reactor.run()
