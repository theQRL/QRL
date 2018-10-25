# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import decimal
from os.path import expanduser
from qrl import __version__ as version

import os

import yaml
from math import ceil, log


class UserConfig(object):
    __instance = None

    def __init__(self, ignore_check=False):
        # TODO: Move to metaclass in Python 3
        if not ignore_check and UserConfig.__instance is not None:
            raise Exception("UserConfig can only be instantiated once")

        UserConfig.__instance = self

        self.genesis_prev_headerhash = b'The sleeper must awaken'
        self.genesis_timestamp = 1530004179
        self.genesis_difficulty = 10000000

        # Default configuration
        self.mining_enabled = False
        self.mining_address = ''
        self.mining_thread_count = 0  # 0 to auto detect thread count based on CPU/GPU number of processors
        self.mining_pause = 0  # this will force a sleep (ms) while mining to reduce cpu usage. Only for mocknet

        # Ephemeral Configuration
        self.accept_ephemeral = True

        # PEER Configuration
        self.max_redundant_connections = 5  # Number of connections allowed from nodes having same IP
        self.enable_peer_discovery = True  # Allows to discover new peers from the connected peers

        self.peer_list = ['35.178.79.137',
                          '35.177.182.85',
                          '18.130.119.29',
                          '18.130.25.64']

        self.p2p_local_port = 19000  # Locally binded port at which node will listen for connection
        self.p2p_public_port = 19000  # Public port forwarding connections to server

        self.peer_rate_limit = 500  # Max Number of messages per minute per peer
        self.p2p_q_size = 10000
        self.outgoing_message_expiry = 90  # Outgoing message expires after 90 seconds

        self.ntp_servers = ['pool.ntp.org', 'ntp.ubuntu.com']
        self.ntp_refresh = 12 * 60 * 60  # 12 hours
        self.ntp_request_timeout = 10  # 10 seconds ntp timeout
        self.ban_minutes = 20  # Allows to ban a peer's IP who is breaking protocol

        self.monitor_connections_interval = 30  # Monitor connection every 30 seconds
        self.max_peers_limit = 100  # Number of allowed peers
        self.chain_state_timeout = 180
        self.chain_state_broadcast_period = 30
        # must be less than ping_timeout

        self.transaction_minimum_fee = int(0 * DevConfig(ignore_check).shor_per_quanta)
        self.transaction_pool_size = 25000
        self.pending_transaction_pool_size = 75000
        # 1% of the pending_transaction_pool will be reserved for moving stale txn
        self.pending_transaction_pool_reserve = int(self.pending_transaction_pool_size * 0.01)
        self.stale_transaction_threshold = 15  # 15 Blocks

        self._qrl_dir = expanduser(os.path.join("~/.qrl"))

        # ======================================
        #        ADMIN API CONFIGURATION
        # ======================================
        self.admin_api_enabled = False
        self.admin_api_host = "127.0.0.1"
        self.admin_api_port = 19008
        self.admin_api_threads = 1
        self.admin_api_max_concurrent_rpc = 100

        # ======================================
        #        PUBLIC API CONFIGURATION
        # ======================================
        self.public_api_enabled = True
        self.public_api_host = "127.0.0.1"
        self.public_api_port = 19009
        self.public_api_threads = 1
        self.public_api_max_concurrent_rpc = 100

        # ======================================
        #        MINING API CONFIGURATION
        # ======================================
        self.mining_api_enabled = False
        self.mining_api_host = "127.0.0.1"
        self.mining_api_port = 19007
        self.mining_api_threads = 1
        self.mining_api_max_concurrent_rpc = 100

        # ======================================
        #        DEBUG API CONFIGURATION
        # ======================================
        self.debug_api_enabled = False
        self.debug_api_host = "127.0.0.1"
        self.debug_api_port = 52134
        self.debug_api_threads = 1
        self.debug_api_max_concurrent_rpc = 100

        # ======================================
        #        GRPC PROXY CONFIGURATION
        # ======================================
        self.grpc_proxy_host = "127.0.0.1"
        self.grpc_proxy_port = 18090

        # ======================================
        #      WALLET DAEMON CONFIGURATION
        # ======================================
        self.public_api_server = "127.0.0.1:19009"
        self.wallet_daemon_host = "127.0.0.1"
        self.wallet_daemon_port = 18091
        self.number_of_slaves = 3

        # ======================================
        #        WALLET API CONFIGURATION
        # ======================================
        self.wallet_api_host = "127.0.0.1"
        self.wallet_api_port = 19010
        self.wallet_api_threads = 1
        self.wallet_api_max_concurrent_rpc = 100

        # WARNING! loading should be the last line.. any new setting after this will not be updated by the config file
        self.load_yaml(self.config_path)
        # WARNING! loading should be the last line.. any new setting after this will not be updated by the config file

    @property
    def qrl_dir(self):
        return self._qrl_dir

    @qrl_dir.setter
    def qrl_dir(self, new_qrl_dir):
        self._qrl_dir = new_qrl_dir
        self.load_yaml(self.config_path)

    @property
    def wallet_dir(self):
        return expanduser(self.qrl_dir)

    @property
    def data_dir(self):
        return expanduser(os.path.join(self.qrl_dir, "data"))

    @property
    def config_path(self):
        return expanduser(os.path.join(self.qrl_dir, "config.yml"))

    @property
    def log_path(self):
        return expanduser(os.path.join(self.qrl_dir, "qrl.log"))

    @property
    def walletd_log_path(self):
        return expanduser(os.path.join(self.qrl_dir, "walletd.log"))

    @property
    def mining_pool_payment_wallet_path(self):
        return expanduser(os.path.join(self.qrl_dir, 'payment_slaves.json'))

    @staticmethod
    def getInstance():
        if UserConfig.__instance is None:
            return UserConfig()
        return UserConfig.__instance

    def load_yaml(self, file_path):
        """
        Overrides default configuration using a yaml file
        :param file_path: The path to the configuration file
        """
        if os.path.isfile(file_path):
            with open(file_path) as f:
                dataMap = yaml.safe_load(f)
                if dataMap is not None:
                    if 'genesis_prev_headerhash' in dataMap:
                        dataMap['genesis_prev_headerhash'] = dataMap['genesis_prev_headerhash'].encode()
                    self.__dict__.update(**dataMap)


def create_path(path):
    # FIXME: Obsolete. Refactor/remove. Use makedirs from python3
    tmp_path = os.path.join(path)
    if not os.path.isdir(tmp_path):
        os.makedirs(tmp_path)


class DevConfig(object):
    __instance = None

    def __init__(self, ignore_check=False):
        super(DevConfig, self).__init__()
        # TODO: Move to metaclass in Python 3
        if not ignore_check and DevConfig.__instance is not None:
            raise Exception("UserConfig can only be instantiated once")

        DevConfig.__instance = self

        self.version = version + ' python'

        ################################################################
        # Warning: Don't change following configuration.               #
        #          For QRL Developers only                             #
        ################################################################

        self.block_lead_timestamp = 30
        self.block_max_drift = 15
        self.max_future_blocks_length = 256
        self.max_margin_block_number = 32
        self.min_margin_block_number = 7

        self.public_ip = None
        self.reorg_limit = 22000
        self.cache_frequency = 1000

        self.message_q_size = 300
        self.message_receipt_timeout = 10  # request timeout for full message
        self.message_buffer_size = 64 * 1024 * 1024  # 64 MB

        self.max_coin_supply = decimal.Decimal(105000000)
        self.coin_remaning_at_genesis = decimal.Decimal(40000000)
        self.timestamp_error = 5  # Error in second

        self.blocks_per_epoch = 100
        self.xmss_tree_height = 12
        self.slave_xmss_height = int(ceil(log(self.blocks_per_epoch * 3, 2)))
        self.slave_xmss_height += self.slave_xmss_height % 2

        # Maximum number of ots index upto which OTS index should be tracked. Any OTS index above the specified value
        # will be managed by OTS Counter
        self.max_ots_tracking_index = 8192
        self.mining_nonce_offset = 39
        self.extra_nonce_offset = 43
        self.mining_blob_size = 76

        self.ots_bitfield_size = ceil(self.max_ots_tracking_index / 8)

        self.default_nonce = 0
        self.default_account_balance = 0 * (10 ** 9)
        self.hash_buffer_size = 4
        self.minimum_minting_delay = 45  # Minimum delay in second before a block is being created
        self.mining_setpoint_blocktime = 60

        self.tx_extra_overhead = 15  # 15 bytes
        self.coinbase_address = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        # Directories and files
        self.db_name = 'state'
        self.peers_filename = 'known_peers.json'
        self.chain_file_directory = 'data'
        self.wallet_dat_filename = 'wallet.json'
        self.slave_dat_filename = 'slave.qrl'
        self.banned_peers_filename = 'banned_peers.qrl'

        self.trust_min_msgcount = 10
        self.trust_min_conntime = 10

        self.supplied_coins = 65000000 * (10 ** 9)

        # ======================================
        #       TRANSACTION CONTROLLER
        # ======================================
        # Max number of output addresses and corresponding data can be added into a list of a transaction
        self.transaction_multi_output_limit = 100

        # ======================================
        #          TOKEN TRANSACTION
        # ======================================
        self.max_token_symbol_length = 10
        self.max_token_name_length = 30

        # ======================================
        #       DIFFICULTY CONTROLLER
        # ======================================
        self.N_measurement = 30
        self.kp = 5

        # ======================================
        #       BLOCK SIZE CONTROLLER
        # ======================================
        self.number_of_blocks_analyze = 10
        self.size_multiplier = 1.1
        self.block_min_size_limit = 1024 * 1024  # 1 MB - Initial Block Size Limit

        # ======================================
        #            P2P SETTINGS
        # ======================================
        self.max_receivable_bytes = 10 * 1024 * 1024  # 10 MB [Temporary Restriction]
        self.reserved_quota = 1024  # 1 KB
        self.max_bytes_out = self.max_receivable_bytes - self.reserved_quota
        self.sync_delay_mining = 60  # Delay mining by 60 seconds while syncing blocks to mainchain

        # ======================================
        #            API SETTINGS
        # ======================================
        self.block_timeseries_size = 1440

        # ======================================
        # SHOR PER QUANTA / MAX ALLOWED DECIMALS
        # ======================================
        self.shor_per_quanta = decimal.Decimal(10 ** 9)

    @staticmethod
    def getInstance():
        if DevConfig.__instance is None:
            return DevConfig()
        return DevConfig.__instance


user = UserConfig.getInstance()
dev = DevConfig.getInstance()
