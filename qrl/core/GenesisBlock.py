# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256, bin2hstr

from qrl.core.blockheader import BlockHeader
from qrl.core import config
from qrl.generated import qrl_pb2


class Singleton(type):
    instance = None

    def __call__(cls, *args, **kw):
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance


class GenesisBlock(object, metaclass=Singleton):
    """
    # first block has no previous header to reference..
    >>> GenesisBlock().blockheader.prev_blockheaderhash == b'1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'
    True
    """

    def __init__(self, protobuf_genesisBlock=None):
        self._data = protobuf_genesisBlock

        if protobuf_genesisBlock is None:
            self._data = qrl_pb2.Block()
            self.blockheader = BlockHeader()
        else:
            self.blockheader = BlockHeader(protobuf_genesisBlock.header)

        self._data.header.MergeFrom(self.blockheader._data)
        self.blockheader._data.hash_header_prev = b'1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'

    @property
    def transactions(self):
        return self._data.transactions

    @property
    def duplicate_transactions(self):
        return self._data.dup_transactions

    @property
    def state(self):
        return self._data.state

    @property
    def stake_list(self):
        return self._data.stake_list

    def set_staking_address(self, staking_address):
        # FIXME: It is odd that we have a hash equal to 'genesis'
        """
        :param chain:
        :type chain:
        :return:
        :rtype:

        >>> GenesisBlock().set_staking_address(None) is not None
        True
        >>> GenesisBlock().set_staking_address(None).blockheader.epoch
        0
        >>> GenesisBlock().set_staking_address(None).blockheader.block_reward
        0
        >>> GenesisBlock().set_staking_address(None).blockheader.blocknumber
        0
        >>> GenesisBlock().set_staking_address(None).blockheader.fee_reward
        0
        >>> GenesisBlock().set_staking_address(None).blockheader.reveal_hash
        b'\\x00\\x00\\x00\\x00\\x00\\x00'
        >>> bin2hstr(GenesisBlock().set_chain(None).blockheader.headerhash)
        '42598eed69acbd031bd30f980f1e383a271d52c954376c184621d73476eb9dda'
        >>> bin2hstr(GenesisBlock().set_chain(None).blockheader.prev_blockheaderhash)
        '584742ee81a520c76ac376f29b9eebd4b73ef0b990e7ff4b994a06be3399be67'
        """
        self.blockheader = self.blockheader.create(staking_address=staking_address,
                                                   blocknumber=0,
                                                   prev_blockheaderhash=bytes(sha2_256(config.dev.genesis_prev_headerhash.encode())),
                                                   hashedtransactions=bytes(sha2_256(b'0')),
                                                   reveal_hash=bytes((0, 0, 0, 0, 0, 0)),
                                                   fee_reward=0)

        self._data.header.MergeFrom(self.blockheader._data)

        return self

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Block()
        Parse(json_data, pbdata)
        return GenesisBlock(pbdata)

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)