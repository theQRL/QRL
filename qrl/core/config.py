# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from os.path import expanduser

import os

import yaml


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
                          '104.251.219.40']  # Atleast one active peer IP required

        self.max_peers_limit = 40  # Number of allowed peers
        self.data_path = expanduser("~/.qrl/data")
        self.wallet_path = expanduser("~/.qrl/wallet")
        self.config_path = '~/.qrl/config.yaml'

        self.load_yaml(expanduser(self.config_path))

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
        self.minimum_required_stakers = 5
        self.minimum_staking_balance_required = 1
        self.blocks_per_epoch = 100
        self.reorg_limit = 3
        self.hashchain_nums = 50  # 1 Primary and rest Secondary hashchain
        self.block_creation_seconds = 55
        self.message_q_size = 300
        self.message_receipt_timeout = 10  # request timeout for full message
        self.stake_before_x_blocks = 50
        self.low_staker_first_hash_block = 70
        self.high_staker_first_hash_block = 80
        self.st_txn_safety_margin = 0.10  # 10% safety margin
        self.N = 256  # Constant used in Block winner formula
        self.POS_delay_after_block = 15
        self.message_buffer_size = 3 * 1024 * 1024  # 3 MB
        self.disk_writes_after_x_blocks = 100
        self.blocks_per_chain_file = 1000
        self.chain_read_buffer_size = 1024
        self.binary_file_delimiter = '-_-_'
        self.compression_level = 1
        self.version_number = "alpha/0.46a"
        self.chain_file_directory = 'data'
        self.transaction_pool_size = 1000
        self.total_coin_supply = 105000000
        self.minimum_minting_delay = 45 # Minimum delay in second before a block is being created
        self.timestamp_error = 5 # Error in second

        self.db_name = 'state'
        self.peers_filename = 'peers.dat'
        self.wallet_dat_filename = 'wallet.dat'
        self.wallet_info_filename = 'wallet.info'
        self.mnemonic_filename = 'mnemonic'
        self.genesis_prev_headerhash = 'Cryptonium'

    @staticmethod
    def getInstance():
        if DevConfig.__instance is None:
            return DevConfig()
        return DevConfig.__instance


user = UserConfig.getInstance()
dev = DevConfig.getInstance()
