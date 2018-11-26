# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse

from qrl.core import config
from qrl.generated import qrl_pb2


class BlockMetadata(object):
    """
    BlockMetadata describes how the Block fits into the chain, like the block's
    difficulty, cumulative difficulty, the hashes of the block's parents and
    children. This is useful for the PoW difficulty calculation.

    Although you could walk through previous blocks to find their parents, in
    practice this could be rather slow. Therefore it was better to just store a
    list of the parent blocks' headerhashes in last_N_headerhashes. With the
    current PoW consensus algorithm, you only have to look back 30 hashes, but
    if a PoS consensus algorithm needs to look back 1000 blocks,
    last_N_headerhashes becomes very useful.

    Blocks always come with their accompanying BlockMetadata when passed around
    between peers. As the node adds a Block to the chain in ChainManager, it
    calculates the difficulty of the network and what should be the next
    difficulty.
    """
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrl_pb2.BlockMetaData()
            self._data.block_difficulty = bytes([0] * 32)
            self._data.cumulative_difficulty = bytes([0] * 32)
        else:
            # TODO: Improve validation
            if len(self.cumulative_difficulty) != 32:
                raise ValueError("Invalid cumulative_difficulty")

            if len(self.block_difficulty) != 32:
                raise ValueError("Invalid block_difficulty")

    @property
    def pbdata(self):
        return self._data

    @property
    def block_difficulty(self):
        return tuple(self._data.block_difficulty)

    @property
    def cumulative_difficulty(self):
        return tuple(self._data.cumulative_difficulty)

    @property
    def child_headerhashes(self):
        return self._data.child_headerhashes

    @property
    def last_N_headerhashes(self):
        return self._data.last_N_headerhashes

    def set_block_difficulty(self, value):

        if len(value) != 32:
            raise ValueError("Invalid block_difficulty")

        self._data.block_difficulty = bytes(value)

    def set_cumulative_difficulty(self, value):
        if len(value) != 32:
            raise ValueError("Invalid cumulative_difficulty")
        self._data.cumulative_difficulty = bytes(value)

    def add_child_headerhash(self, child_headerhash: bytes):
        if child_headerhash not in self._data.child_headerhashes:
            self._data.child_headerhashes.append(child_headerhash)

    def update_last_headerhashes(self, parent_last_N_headerhashes, last_headerhash: bytes):
        del self._data.last_N_headerhashes[:]
        self._data.last_N_headerhashes.extend(parent_last_N_headerhashes)
        self._data.last_N_headerhashes.append(last_headerhash)
        if len(self._data.last_N_headerhashes) > config.dev.N_measurement:
            del self._data.last_N_headerhashes[0]

        if len(self._data.last_N_headerhashes) > config.dev.N_measurement:
            raise Exception('Size of last_N_headerhashes is more than expected %s %s',
                            len(self._data.last_N_headerhashes),
                            config.dev.N_measurement)

    @staticmethod
    def create(block_difficulty=bytes([0] * 32),
               cumulative_difficulty=bytes([0] * 32),
               child_headerhashes=None):
        block_meta_data = BlockMetadata()
        block_meta_data._data.block_difficulty = block_difficulty
        block_meta_data._data.cumulative_difficulty = cumulative_difficulty

        if child_headerhashes:
            for headerhash in child_headerhashes:
                block_meta_data._data.child_headerhashes.append(headerhash)

        return block_meta_data

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.BlockMetaData()
        Parse(json_data, pbdata)
        return BlockMetadata(pbdata)

    def to_json(self) -> str:
        return MessageToJson(self._data, sort_keys=True).encode()

    def serialize(self) -> str:
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrl_pb2.BlockMetaData()
        pbdata.ParseFromString(bytes(data))
        return BlockMetadata(pbdata)
