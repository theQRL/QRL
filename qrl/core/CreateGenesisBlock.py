# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os

import yaml

from blockheader import BlockHeader
from qrl.crypto.misc import sha256
from qrl.core import config

genesis_info = dict()


class CreateGenesisBlock(object):  # first block has no previous header to reference..
    def __init__(self, chain):
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain,
                                blocknumber=0,
                                hashchain_link='genesis',
                                prev_blockheaderhash=sha256(config.dev.genesis_prev_headerhash),
                                hashedtransactions=sha256('0'),
                                reveal_list=[],
                                vote_hashes=[],
                                fee_reward=0)
        self.transactions = []
        self.stake = []
        self.state = []

        package_directory = os.path.dirname(os.path.abspath(__file__))
        genesis_data_path = os.path.join(package_directory, 'genesis.yml')
        with open(genesis_data_path) as f:
            dataMap = yaml.safe_load(f)
            genesis_info.update(dataMap['genesis_info'])

        for key in genesis_info:
            self.state.append([key, [0, genesis_info[key] * 100000000, []]])

        self.stake_list = []
        for stake in self.state:
            self.stake_list.append(stake[0])

        self.stake_seed = '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'
