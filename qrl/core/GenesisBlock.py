# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os

import yaml

from blockheader import BlockHeader
from qrl.crypto.misc import sha256
from qrl.core import config


class Singleton(type):
    instance = None

    def __call__(cls, *args, **kw):
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance


class GenesisBlock(object):
    """
    # first block has no previous header to reference..
    >>> GenesisBlock().stake_seed == '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'
    True
    >>> len(GenesisBlock().stake_list)
    5
    """
    __metaclass__ = Singleton

    def __init__(self):
        self._genesis_info = dict()
        package_directory = os.path.dirname(os.path.abspath(__file__))
        genesis_data_path = os.path.join(package_directory, 'genesis.yml')

        with open(genesis_data_path) as f:
            dataMap = yaml.safe_load(f)
            self._genesis_info.update(dataMap['genesis_info'])

        self.blockheader = BlockHeader()
        self.transactions = []
        self.stake = []
        self.state = []

        for key in self._genesis_info:
            self.state.append([key, [0, self._genesis_info[key] * 100000000, []]])

        self.stake_list = []
        for stake in self.state:
            self.stake_list.append(stake[0])

        self.stake_seed = '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'

    def set_chain(self, chain):
        # FIXME: It is odd that we have a hash equal to 'genesis'
        """
        :param chain:
        :type chain:
        :return:
        :rtype:
        >>> GenesisBlock().set_chain(None) is not None
        True
        >>> GenesisBlock().set_chain(None).blockheader.epoch
        0
        >>> GenesisBlock().set_chain(None).blockheader.block_reward
        0
        >>> GenesisBlock().set_chain(None).blockheader.blocknumber
        0
        >>> GenesisBlock().set_chain(None).blockheader.fee_reward
        0
        >>> GenesisBlock().set_chain(None).blockheader.reveal_hash
        'genesis'
        >>> GenesisBlock().set_chain(None).blockheader.headerhash
        'f16eb270d0880a2807ecc4d36de431e3b2c09538bfa3115b2935091d8c038041'
        >>> GenesisBlock().set_chain(None).blockheader.prev_blockheaderhash
        '2b47d12f00182206e19bb22388a20d469c5c904a602a81a4e990c40c208d799f'
        """
        self.blockheader.create(chain=chain,
                                blocknumber=0,
                                prev_blockheaderhash=sha256(config.dev.genesis_prev_headerhash),
                                hashedtransactions=sha256('0'),
                                reveal_hash='genesis',
                                vote_hash='genesis',
                                fee_reward=0)
        return self

    def get_info(self):
        """
        :return:
        :rtype:
        >>> GenesisBlock().get_info() is not None
        True
        """
        return self._genesis_info
