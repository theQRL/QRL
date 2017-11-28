# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from os.path import expanduser
from qrl import __version__ as version

import os

import yaml
from math import ceil, log


class UserConfig(object):
    __instance = None

    def __init__(self):
        # TODO: Move to metaclass in Python 3
        if UserConfig.__instance is not None:
            raise Exception("UserConfig can only be instantiated once")

        UserConfig.__instance = self

        # Default configuration
        self.enable_auto_staking = True

        # PEER Configuration
        self.enable_peer_discovery = True  # Allows to discover new peers from the connected peers
        self.peer_list = ['104.237.3.184',
                          '104.237.3.185',
                          '104.251.219.215',
                          '104.251.219.145',
                          '104.251.219.40']             # Atleast one active peer IP required

        self.max_peers_limit = 100  # Number of allowed peers
        self.ping_timeout = 180
        self.ping_frequency = 20  # How frequently a node should ping (in seconds)
        # must be less than ping_timeout

        self.qrl_dir = os.path.join(expanduser("~"), ".qrl")

        self.data_path = os.path.join(self.qrl_dir, "data")
        self.wallet_path = os.path.join(self.qrl_dir, "wallet")
        self.config_path = os.path.join(self.qrl_dir, "config.yml")
        self.log_path = os.path.join(self.qrl_dir, "qrl.log")

        self.load_yaml(self.config_path)

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
                    self.__dict__.update(**dataMap)


def create_path(path):
    # FIXME: Obsolete. Refactor/remove. Use makedirs from python3
    tmp_path = os.path.join(path)
    if not os.path.isdir(tmp_path):
        os.makedirs(tmp_path)


class DevConfig(object):
    __instance = None

    def __init__(self):
        super(DevConfig, self).__init__()
        # TODO: Move to metaclass in Python 3
        if DevConfig.__instance is not None:
            raise Exception("UserConfig can only be instantiated once")

        DevConfig.__instance = self

        ################################################################
        # Warning: Don't change following configuration.               #
        #          For QRL Developers only                             #
        ################################################################
        self.public_ip = None
        self.minimum_required_stakers = 4
        self.minimum_staking_balance_required = 1
        self.blocks_per_epoch = 100
        self.reorg_limit = 2
        self.message_q_size = 300
        self.message_receipt_timeout = 10  # request timeout for full message
        self.N = 256  # Constant used in Block winner formula
        self.POS_delay_after_block = 15
        self.message_buffer_size = 3 * 1024 * 1024  # 3 MB
        self.disk_writes_after_x_blocks = 100
        self.blocks_per_chain_file = 1000
        self.chain_read_buffer_size = 1024
        self.binary_file_delimiter = b'-_-_'
        self.compression_level = 1
        self.version = version
        self.chain_file_directory = 'data'
        self.transaction_pool_size = 1000
        self.max_coin_supply = 105000000
        self.timestamp_error = 5  # Error in second
        self.slave_xmss_height = int(ceil(log(self.blocks_per_epoch * 3, 2)))
        self.slave_xmss_height = self.slave_xmss_height + (self.slave_xmss_height & 0x1)
        self.xmss_tree_height = 10
        self.default_nonce = 0
        self.default_account_balance = 100 * (10 ** 8)
        self.stamping_series = [5, 10, 20, 30, 40, 50, 60, 70, 80, 100]
        self.hash_buffer_size = 4
        self.minimum_minting_delay = 45  # Minimum delay in second before a block is being created
        self.vote_x_seconds_before_next_block = 15  # Vote will be done X seconds before creation of next block
        # Must be less than minimum_minting_delay
        self.max_consensus_retry = 5
        self.db_name = 'state'
        self.peers_filename = 'peers.qrl'

        self.wallet_dat_filename = 'wallet.qrl'
        self.wallet_old_dat_filename = 'wallet.json'

        self.slave_dat_filename = 'slave.qrl'
        self.mnemonic_filename = 'mnemonic'
        self.genesis_prev_headerhash = 'Earth abides'

    @staticmethod
    def getInstance():
        if DevConfig.__instance is None:
            return DevConfig()
        return DevConfig.__instance


user = UserConfig.getInstance()
dev = DevConfig.getInstance()
