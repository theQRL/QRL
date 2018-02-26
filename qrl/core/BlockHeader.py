# coding=utf-8
import functools
from google.protobuf.json_format import MessageToJson, Parse
from pyqryptonight.pyqryptonight import Qryptonight

from qrl.core import config
from qrl.core.formulas import block_reward
from qrl.core.misc import ntp, logger
from qrl.generated import qrl_pb2


class BlockHeader(object):
    def __init__(self, protobuf_blockheader=None):
        """
        >>> BlockHeader() is not None
        True
        """
        self._data = protobuf_blockheader
        if protobuf_blockheader is None:
            self._data = qrl_pb2.BlockHeader()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf BlockHeader object
        :rtype: qrl_pb2.BlockHeader
        """
        return self._data

    @property
    def block_number(self):
        return self._data.block_number

    @property
    def epoch(self):
        return self._data.block_number // config.dev.blocks_per_epoch

    @property
    def timestamp(self):
        return self._data.timestamp_seconds

    @property
    def headerhash(self):
        return self._data.hash_header

    @property
    def prev_blockheaderhash(self):
        return self._data.hash_header_prev

    @property
    def block_reward(self):
        return self._data.reward_block

    @property
    def fee_reward(self):
        return self._data.reward_fee

    @property
    def tx_merkle_root(self):
        return self._data.merkle_root

    @property
    def PK(self):
        return self._data.PK

    @property
    def mining_nonce(self):
        return self._data.mining_nonce

    @property
    def nonce_offset(self):
        return config.dev.mining_nonce_offset

    @property
    def mining_blob(self) -> bytes:
        blob = self.block_number.to_bytes(8, byteorder='big', signed=False) \
               + self.timestamp.to_bytes(8, byteorder='big', signed=False) \
               + self.prev_blockheaderhash \
               + self.block_reward.to_bytes(8, byteorder='big', signed=False) \
               + self.fee_reward.to_bytes(8, byteorder='big', signed=False) \
               + self.tx_merkle_root \
               + self.PK

        if len(blob) < self.nonce_offset:
            raise Exception("Mining blob size below 39 bytes")

        # Now insert mining nonce in offset 39 for compatibility
        mining_nonce_bytes = self.mining_nonce.to_bytes(4, byteorder='big', signed=False)
        blob = blob[:self.nonce_offset] + mining_nonce_bytes + blob[self.nonce_offset:]

        return bytes(blob)

    @functools.lru_cache(maxsize=5)
    def _get_qryptonight_hash(self, blob):
        qn = Qryptonight()
        return bytes(qn.hash(blob))

    def generate_headerhash(self):
        return self._get_qryptonight_hash(self.mining_blob)

    @staticmethod
    def create(blocknumber: int,
               PK: bytes,
               prev_blockheaderhash: bytes,
               hashedtransactions: bytes,
               fee_reward: int):
        """
        Create a block header based on the parameters

        >>> BlockHeader.create(blocknumber=1, PK=b'publickey',
        ...                    prev_blockheaderhash=b'headerhash',
        ...                    hashedtransactions=b'some_data', fee_reward=1) is not None
        True
        >>> b=BlockHeader.create(blocknumber=1, PK=b'publickey',
        ...                       prev_blockheaderhash=b'headerhash',
        ...                       hashedtransactions=b'some_data', fee_reward=1)
        >>> b.epoch
        0
        """

        bh = BlockHeader()
        bh._data.block_number = blocknumber

        if bh._data.block_number != 0:
            bh._data.timestamp_seconds = int(ntp.getTime())
            if bh._data.timestamp_seconds == 0:
                logger.warning('Failed to get NTP timestamp')
                return

        bh._data.hash_header_prev = prev_blockheaderhash
        bh._data.merkle_root = hashedtransactions
        bh._data.PK = PK
        bh._data.reward_fee = fee_reward

        bh._data.reward_block = 0

        if bh._data.block_number != 0:
            bh._data.reward_block = bh.block_reward_calc()

        bh.set_mining_nonce(0)
        return bh

    def set_mining_nonce(self, value):
        self._data.mining_nonce = value
        self._data.hash_header = self.generate_headerhash()

    def block_reward_calc(self):
        """
        return block reward for the block_n
        :return:
        """
        return int(block_reward(self.block_number))

    def validate(self, fee_reward, coinbase_amount):
        current_time = ntp.getTime()
        allowed_timestamp = current_time + config.dev.block_lead_timestamp
        if self.timestamp > allowed_timestamp:
            logger.warning('BLOCK timestamp is more than the allowed block lead timestamp')
            logger.warning('Block timestamp %s ', self.timestamp)
            logger.warning('threshold timestamp %s', allowed_timestamp)
            return False

        if self.timestamp < config.dev.genesis_timestamp:
            logger.warning('Timestamp lower than genesis timestamp')
            logger.warning('Genesis Timestamp %s', config.dev.genesis_timestamp)
            logger.warning('Block Timestamp %s', self.timestamp)
            return False

        if self.generate_headerhash() != self.headerhash:
            logger.warning('Headerhash false for block: failed validation')
            return False

        if self.block_reward != self.block_reward_calc():
            logger.warning('Block reward incorrect for block: failed validation')
            return False

        if self.fee_reward != fee_reward:
            logger.warning('Block Fee reward incorrect for block: failed validation')
            return False

        if self.block_reward + self.fee_reward != coinbase_amount:
            logger.warning('Block_reward + fee_reward doesnt sums up to coinbase_amount')
            return False

        if self.timestamp == 0 and self.block_number > 0:
            logger.warning('Invalid block timestamp ')
            return False

        return True

    def validate_parent_child_relation(self, parent_block):
        if parent_block.block_number != self.block_number - 1:
            logger.warning('Block numbers out of sequence: failed validation')
            return False

        if parent_block.headerhash != self.prev_blockheaderhash:
            logger.warning('Headerhash not in sequence: failed validation')
            return False

        if self.timestamp < parent_block.timestamp:
            logger.warning('BLOCK timestamp is less than prev block timestamp')
            logger.warning('block timestamp %s ', self.timestamp)
            logger.warning('must be greater than or equals to %s', parent_block.timestamp)
            return False

        return True

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.BlockHeader()
        Parse(json_data, pbdata)
        return BlockHeader(pbdata)

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)
