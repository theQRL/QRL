# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
import faulthandler
import os

from mock import MagicMock
from twisted.internet import reactor
from pyqrllib.pyqrllib import hstr2bin, bin2hstr

from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.misc import ntp, logger, set_logger
from qrl.core.qrlnode import QRLNode
from qrl.services.services import start_services
from qrl.core import config
from qrl.core.State import State


def parse_arguments():
    parser = argparse.ArgumentParser(description='QRL node')
    parser.add_argument('--mining_thread_count', '-m', dest='mining_thread_count', type=int, required=False,
                        default=None, help="Number of threads for mining")
    parser.add_argument('--quiet', '-q', dest='quiet', action='store_true', required=False, default=False,
                        help="Avoid writing data to the console")
    parser.add_argument('--qrldir', '-d', dest='qrl_dir', default=config.user.qrl_dir,
                        help="Use a different directory for node data/configuration")
    parser.add_argument('--no-colors', dest='no_colors', action='store_true', default=False,
                        help="Disables color output")
    parser.add_argument("-l", "--loglevel", dest="logLevel", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")
    parser.add_argument('--network-type', dest='network_type', choices=['mainnet', 'testnet'],
                        default='mainnet', required=False, help="Runs QRL Testnet Node")
    parser.add_argument('--miningAddress', dest='mining_address', required=False,
                        help="QRL Wallet address on which mining reward has to be credited.")
    parser.add_argument('--mockGetMeasurement', dest='measurement', required=False, type=int, default=-1,
                        help="Warning: Only for integration test, to mock get_measurement")
    parser.add_argument('--debug', dest='debug', action='store_true', default=False,
                        help="Enables fault handler")
    parser.add_argument('--mocknet', dest='mocknet', action='store_true', default=False,
                        help="Enables default mocknet settings")
    return parser.parse_args()


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

    qrl_dir_post_fix = ''
    copy_files = []
    if args.network_type == 'testnet':
        # Hard Fork Block Height For Testnet
        config.dev.hard_fork_heights = list(config.dev.testnet_hard_fork_heights)
        # Hard Fork Block Height Disconnect Delay For Testnet
        config.dev.hard_fork_node_disconnect_delay = list(config.dev.testnet_hard_fork_node_disconnect_delay)
        qrl_dir_post_fix = '-testnet'
        package_directory = os.path.dirname(os.path.abspath(__file__))
        copy_files.append(os.path.join(package_directory, 'network/testnet/genesis.yml'))
        copy_files.append(os.path.join(package_directory, 'network/testnet/config.yml'))

    logger.debug("=====================================================================================")
    logger.info("QRL Path: %s", args.qrl_dir)
    config.user.qrl_dir = os.path.expanduser(os.path.normpath(args.qrl_dir) + qrl_dir_post_fix)
    config.create_path(config.user.qrl_dir, copy_files)
    config.user.load_yaml(config.user.config_path)

    if args.mining_thread_count is None:
        args.mining_thread_count = config.user.mining_thread_count
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
        config.dev.pbdata.block.block_timing_in_seconds = 1
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

    chain_manager = ChainManager(state=persistent_state)
    if args.measurement > -1:
        chain_manager.get_measurement = MagicMock(return_value=args.measurement)

    chain_manager.load(Block.deserialize(GenesisBlock().serialize()))

    qrlnode = QRLNode(mining_address=mining_address)
    qrlnode.set_chain_manager(chain_manager)

    set_logger.set_logger(args, qrlnode.sync_state)

    #######
    # NOTE: Keep assigned to a variable or might get collected
    admin_service, grpc_service, mining_service, debug_service = start_services(qrlnode)

    qrlnode.start_listening()

    qrlnode.start_pow(args.mining_thread_count)

    logger.info('QRL blockchain ledger %s', config.dev.version)
    if config.user.mining_enabled:
        logger.info('Mining/staking address %s using %s threads (0 = auto)', 'Q' + bin2hstr(mining_address), args.mining_thread_count)

    elif args.mining_address or args.mining_thread_count:
        logger.warning('Mining is not enabled but you sent some "mining related" param via CLI')

    reactor.run()
