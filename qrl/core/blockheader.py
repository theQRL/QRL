# coding=utf-8
from pyqrllib.pyqrllib import sha2_256, str2bin
from qrl.core import ntp, logger, config
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
    def blocknumber(self):
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
    def reveal_hash(self):
        return self._data.hash_reveal

    @property
    def stake_selector(self):
        return self._data.stake_selector

    def create(self,
               chain,
               blocknumber,
               prev_blockheaderhash,
               hashedtransactions,
               reveal_hash,
               fee_reward):
        """
        Create a block header based on the parameters
        :param chain:
        :param blocknumber:
        :param prev_blockheaderhash:
        :param hashedtransactions:
        :param reveal_hash:
        :param fee_reward:
        :return:

        >>> BlockHeader().create(None, 0, b'0', b'0', b'0', 1) is not None
        True
        >>> b = BlockHeader().create(None, 0, b'0', b'0', b'0', 1); b.epoch
        0
        >>> b = BlockHeader().create(None, 0, b'0', b'0', b'0', 1); b.epoch
        0
        """

        self._data.block_number = blocknumber
        self._data.epoch = self._data.block_number // config.dev.blocks_per_epoch

        if self._data.block_number != 0:
            self._data.timestamp.seconds = int(ntp.getTime())
            if self._data.timestamp == 0:
                logger.warning('Failed to get NTP timestamp')
                return

        self._data.hash_header_prev = prev_blockheaderhash
        self._data.merkle_root = hashedtransactions
        self._data.hash_reveal = reveal_hash
        self._data.reward_fee = fee_reward

        self._data.stake_selector = b''
        self._data.reward_block = 0

        if self._data.block_number != 0:
            self._data.stake_selector = chain.mining_address
            self._data.reward_block = self.block_reward_calc()

        self._data.hash_header = self.generate_headerhash()

        return self

    def generate_headerhash(self):
        # FIXME: This is using strings... fix
        data = "{0}{1}{2}{3}{4}{5}{6}{7}{8}".format(self.stake_selector,
                                                    self.epoch,
                                                    self.block_reward,
                                                    self.fee_reward,
                                                    self.timestamp,
                                                    self.blocknumber,
                                                    self.prev_blockheaderhash,
                                                    self.tx_merkle_root,
                                                    self.reveal_hash)
        return bytes(sha2_256(str2bin(data)))

    def block_reward_calc(self):
        """
        return block reward for the block_n
        :return:
        """
        return block_reward_calc(self.blocknumber)

    def validate(self, last_header):
        if last_header.blocknumber != self.blocknumber - 1:
            logger.warning('Block numbers out of sequence: failed validation')
            return False

        if last_header.headerhash != self.prev_blockheaderhash:
            logger.warning('Headerhash not in sequence: failed validation')
            return False

        if self.generate_headerhash() != self.headerhash:
            logger.warning('Headerhash false for block: failed validation')
            return False

        if self.block_reward != self.block_reward_calc():
            logger.warning('Block reward incorrect for block: failed validation')
            return False

        if self.epoch != self.blocknumber // config.dev.blocks_per_epoch:
            logger.warning('Epoch incorrect for block: failed validation')
            return False

        if self.timestamp == 0 and self.blocknumber > 0:
            logger.warning('Invalid block timestamp ')
            return False

        if self.timestamp <= last_header.timestamp:
            logger.warning('BLOCK timestamp is less than prev block timestamp')
            logger.warning('block timestamp %s ', self.timestamp)
            logger.warning('must be greater than %s', last_header.timestamp)
            return False

        if last_header.timestamp + config.dev.minimum_minting_delay > self.timestamp:
            logger.warning('BLOCK created without waiting for minimum minting delay')
            logger.warning('prev_block timestamp %s ', last_header.timestamp)
            logger.warning('current_block timestamp %s ', self.timestamp)
            return False

        return True

    def validate_block_timestamp(self, last_block_timestamp):
        # TODO: Add minimum minting delay
        if last_block_timestamp >= self.timestamp:
            return False

        curr_time = ntp.getTime()
        if curr_time == 0:
            return False

        max_block_number = int((curr_time - last_block_timestamp) / config.dev.block_creation_seconds)
        if self.blocknumber > max_block_number:
            return False

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.BlockHeader()
        Parse(json_data, pbdata)
        return BlockHeader(pbdata)

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)
