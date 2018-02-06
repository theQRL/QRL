# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse

from qrl.generated import qrl_pb2
from qrl.core import config


class BlockMetadata(object):

    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrl_pb2.BlockMetaData()

    @property
    def is_orphan(self):
        return self._data.is_orphan

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

    def set_orphan(self, value):
        self._data.is_orphan = value

    def set_block_difficulty(self, value):
        self._data.block_difficulty = bytes(value)

    def set_cumulative_difficulty(self, value):
        self._data.cumulative_difficulty = bytes(value)

    def add_child_headerhash(self, child_headerhash: bytes):
        self._data.child_headerhashes.append(child_headerhash)

    def update_last_headerhashes(self, parent_last_N_headerhashes, last_headerhash: bytes):
        self._data.last_N_headerhashes.extend(parent_last_N_headerhashes)
        self._data.last_N_headerhashes.append(last_headerhash)
        if len(self._data.last_N_headerhashes) > config.dev.N_measurement:
            del self._data.last_N_headerhashes[0]

    @staticmethod
    def create(is_orphan=True, block_difficulty=b'\x00'*32, cumulative_difficulty=b'\x00'*32, child_headerhashes=None):
        block_meta_data = BlockMetadata()
        block_meta_data._data.is_orphan = is_orphan
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
        return MessageToJson(self._data).encode()
