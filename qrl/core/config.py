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
        self.mining_enabled = True
        self.mining_thread_count = 2  # TODO: -1 to auto detect thread count based on CPU/GPU num. of processors
        self.reward_address = b'Qa02d909723512ecd1606c96f52f5a4121946f068986e612a57c75353952ab3624ddd0bd6'

        # Ephemeral Configuration
        self.accept_ephemeral = True

        # PEER Configuration
        self.enable_peer_discovery = True  # Allows to discover new peers from the connected peers
        self.peer_list = ['45.76.139.109',
                          '45.77.88.205']

        self.max_peers_limit = 100  # Number of allowed peers
        self.ping_timeout = 180
        self.ping_period = 10
        # must be less than ping_timeout

        self.qrl_dir = os.path.join(expanduser("~"), ".qrl")
        self.data_dir = os.path.join(self.qrl_dir, "data")
        self.config_path = os.path.join(self.qrl_dir, "config.yml")
        self.log_path = os.path.join(self.qrl_dir, "qrl.log")
        self.wallet_staking_dir = os.path.join(self.qrl_dir, "wallet")

        self.wallet_dir = os.path.join(self.qrl_dir)

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

        self.version = version
        self.required_version = '0.0.'
        self.genesis_prev_headerhash = b'Rescue Party'

        ################################################################
        # Warning: Don't change following configuration.               #
        #          For QRL Developers only                             #
        ################################################################

        self.public_ip = None
        self.reorg_limit = 2

        self.message_q_size = 300
        self.message_receipt_timeout = 10  # request timeout for full message
        self.message_buffer_size = 3 * 1024 * 1024  # 3 MB

        self.blocks_per_chain_file = 1000
        self.chain_read_buffer_size = 1024

        self.transaction_pool_size = 1000
        self.max_coin_supply = 105000000
        self.timestamp_error = 5  # Error in second

        self.blocks_per_epoch = 100
        self.xmss_tree_height = 12
        self.slave_xmss_height = int(ceil(log(self.blocks_per_epoch * 3, 2)))
        self.slave_xmss_height += self.slave_xmss_height % 2

        self.ots_bitfield_size = ceil((2 ** self.xmss_tree_height) / 8)

        self.default_nonce = 0
        self.default_account_balance = 100 * (10 ** 9)
        self.hash_buffer_size = 4
        self.minimum_minting_delay = 45  # Minimum delay in second before a block is being created
        self.genesis_difficulty = 5000

        # Directories and files
        self.db_name = 'state'
        self.peers_filename = 'peers.qrl'
        self.chain_file_directory = 'data'
        self.wallet_dat_filename = 'wallet.qrl'
        self.slave_dat_filename = 'slave.qrl'

    @staticmethod
    def getInstance():
        if DevConfig.__instance is None:
            return DevConfig()
        return DevConfig.__instance


user = UserConfig.getInstance()
dev = DevConfig.getInstance()
