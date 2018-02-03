# coding=utf-8
from pyqrllib.pyqrllib import sha2_256, str2bin
from qrl.core import config
from qrl.core.misc import ntp, logger
from qrl.core.formulas import block_reward_calc
from qrl.generated import qrl_pb2
from google.protobuf.json_format import MessageToJson, Parse


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
        return self._data.epoch

    @property
    def timestamp(self):
        return self._data.timestamp.seconds

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
    def mining_hash(self):
        data = "{0}{1}{2}{3}{4}{5}{6}{7}".format(self.PK,
                                                 self.epoch,
                                                 self.block_reward,
                                                 self.fee_reward,
                                                 self.timestamp,
                                                 self.block_number,
                                                 self.prev_blockheaderhash,
                                                 self.tx_merkle_root)
        return bytes(sha2_256(str2bin(data)))

    @staticmethod
    def create(blocknumber: int,
               mining_nonce: int,
               PK: bytes,
               prev_blockheaderhash: bytes,
               hashedtransactions: bytes,
               fee_reward: int):
        """
        Create a block header based on the parameters

        >>> BlockHeader.create(blocknumber=1, mining_nonce=1, PK=b'publickey',
        ...                    prev_blockheaderhash=b'headerhash',
        ...                    hashedtransactions=b'some_data', fee_reward=1) is not None
        True
        >>> b=BlockHeader.create(blocknumber=1, mining_nonce=1, PK=b'publickey',
        ...                       prev_blockheaderhash=b'headerhash',
        ...                       hashedtransactions=b'some_data', fee_reward=1)
        >>> b.epoch
        0
        """

        bh = BlockHeader()
        bh._data.block_number = blocknumber
        bh._data.epoch = bh._data.block_number // config.dev.blocks_per_epoch

        if bh._data.block_number != 0:
            bh._data.timestamp.seconds = int(ntp.getTime())
            if bh._data.timestamp == 0:
                logger.warning('Failed to get NTP timestamp')
                return

        bh._data.hash_header_prev = prev_blockheaderhash
        bh._data.merkle_root = hashedtransactions
        bh._data.PK = PK
        bh._data.reward_fee = fee_reward

        bh._data.reward_block = 0

        if bh._data.block_number != 0:
            bh._data.reward_block = bh.block_reward_calc()

        bh.set_mining_nonce(mining_nonce)
        return bh

    def set_mining_nonce(self, value):
        self._data.mining_nonce = value
        self._data.hash_header = self.generate_headerhash()

    def generate_headerhash(self):
        # FIXME: This is using strings... fix
        data = "{0}{1}{2}{3}{4}{5}{6}{7}{8}".format(self.PK,
                                                    self.epoch,
                                                    self.block_reward,
                                                    self.fee_reward,
                                                    self.timestamp,
                                                    self.block_number,
                                                    self.prev_blockheaderhash,
                                                    self.tx_merkle_root,
                                                    self.mining_nonce)
        return bytes(sha2_256(str2bin(data)))

    def block_reward_calc(self):
        """
        return block reward for the block_n
        :return:
        """
        return block_reward_calc(self.block_number)

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

        max_blocknumber = (current_time - config.dev.genesis_timestamp) / 60
        max_expected_blocknumber = max_blocknumber + config.dev.max_margin_block_number
        if self.block_number > max_expected_blocknumber:
            logger.warning('Blocknumber exceeds maximum expected blocknumbers')
            logger.warning('Max expected blocknumber %s', max_expected_blocknumber)
            logger.warning('Blocknumber found %s', self.block_number)
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

        if self.epoch != self.block_number // config.dev.blocks_per_epoch:
            logger.warning('Epoch incorrect for block: failed validation')
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
