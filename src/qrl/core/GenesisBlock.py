# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os

import yaml
import simplejson as json
from google.protobuf.json_format import Parse

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.Singleton import Singleton
from qrl.generated import qrl_pb2


class GenesisBlock(Block, metaclass=Singleton):
    def __init__(self):
        package_directory = os.path.dirname(os.path.abspath(__file__))

        genesis_data_path = os.path.join(package_directory, 'genesis.yml')
        genesis_config_path = os.path.join(config.user.qrl_dir, 'genesis.yml')

        if os.path.isfile(genesis_config_path):
            with open(genesis_config_path) as f:
                genesisBlock_json = json.dumps(yaml.safe_load(f))
        else:
            with open(genesis_data_path) as f:
                genesisBlock_json = json.dumps(yaml.safe_load(f))

        tmp_block = qrl_pb2.Block()
        Parse(genesisBlock_json, tmp_block)
        super(GenesisBlock, self).__init__(tmp_block)

    @property
    def transactions(self):
        return self._data.transactions

    @property
    def genesis_balance(self):
        return self._data.genesis_balance
