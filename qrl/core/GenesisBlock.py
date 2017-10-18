# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os

import yaml

from pyqrllib.pyqrllib import sha2_256, bin2hstr
from qrl.core.blockheader import BlockHeader
from qrl.core import config, logger


class Singleton(type):
    instance = None

    def __call__(cls, *args, **kw):
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance


class GenesisBlock(object, metaclass=Singleton):
    """
    # first block has no previous header to reference..
    >>> GenesisBlock().stake_seed == '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'
    True
    >>> len(GenesisBlock().stake_list)
    5
    """

    def __init__(self):
        self._genesis_info = dict()
        package_directory = os.path.dirname(os.path.abspath(__file__))
        genesis_data_path = os.path.join(package_directory, 'genesis.yml')

        with open(genesis_data_path) as f:
            logger.info("Loading genesis from %s", genesis_data_path)
            dataMap = yaml.safe_load(f)
            for key in dataMap['genesis_info']:
                self._genesis_info[key.encode()] = dataMap['genesis_info'][key]

        self.blockheader = BlockHeader()
        self.transactions = []
        self.duplicate_transactions = []
        self.stake = []
        self.state = []

        for key in self._genesis_info:
            # FIXME: Magic number? Unify
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
        >>> bin2hstr(GenesisBlock().set_chain(None).blockheader.headerhash)
        '22388dd5e1a6ab7b1802075b199dddf7d99c9b14602fdc9038e8263c88a42ff5'
        >>> bin2hstr(GenesisBlock().set_chain(None).blockheader.prev_blockheaderhash)
        'c593bc8feea0099ddd3a4a457150ca215499d680c49bbc4c2c24a72f2179439d'
        """
        self.blockheader.create(chain=chain,
                                blocknumber=0,
                                prev_blockheaderhash=bytes(sha2_256(config.dev.genesis_prev_headerhash.encode())),
                                hashedtransactions=bytes(sha2_256(b'0')),
                                reveal_hash=bytes((0, 0, 0, 0, 0, 0)),
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
