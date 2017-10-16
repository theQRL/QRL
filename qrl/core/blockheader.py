# coding=utf-8
from pyqrllib.pyqrllib import sha2_256, str2bin
from qrl.core import ntp, logger, config
from qrl.core.formulas import block_reward_calc


class BlockHeader(object):
    def __init__(self):
        """
        >>> BlockHeader() is not None
        True
        """
        self.blocknumber = None
        self.epoch = None
        self.timestamp = None

        self.headerhash = None
        self.prev_blockheaderhash = None

        self.block_reward = None
        self.fee_reward = 0

        self.tx_merkle_root = None
        self.reveal_hash = None
        self.stake_selector = None

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

        >>> BlockHeader().create(None, 0, b'0', b'0', b'0', b'0', 0.1) is None
        True
        >>> b = BlockHeader(); b.create(None, 0, b'0', b'0', b'0', b'0', 0.1); b.epoch
        0
        >>> b = BlockHeader(); b.create(None, 0, b'0', b'0', b'0', b'0', 0.1); b.epoch # doctest: +SKIP
        0
        """

        self.blocknumber = blocknumber
        self.timestamp = 0
        self.epoch = self.blocknumber // config.dev.blocks_per_epoch

        if self.blocknumber != 0:
            self.timestamp = int(ntp.getTime())
            if self.timestamp == 0:
                logger.warning('Failed to get NTP timestamp')
                return

        self.prev_blockheaderhash = prev_blockheaderhash
        self.tx_merkle_root = hashedtransactions
        self.reveal_hash = reveal_hash
        self.fee_reward = fee_reward

        self.stake_selector = ''
        self.block_reward = 0

        if self.blocknumber != 0:
            self.stake_selector = chain.mining_address
            self.block_reward = self.block_reward_calc()

        self.headerhash = self.generate_headerhash()

    @staticmethod
    def from_json(json_blockheader):
        tmp = BlockHeader()

        # TODO: Moving to protobuf?
        tmp.blocknumber = json_blockheader['blocknumber']
        tmp.epoch = json_blockheader['epoch']
        tmp.timestamp = json_blockheader['timestamp']

        tmp.headerhash = tuple(json_blockheader['headerhash'])
        tmp.prev_blockheaderhash = tuple(json_blockheader['prev_blockheaderhash'])

        tmp.block_reward = json_blockheader['block_reward']
        tmp.fee_reward = json_blockheader['fee_reward']

        tmp.tx_merkle_root = tuple(json_blockheader['tx_merkle_root'])
        tmp.reveal_hash = tuple(json_blockheader['reveal_hash'])
        tmp.stake_selector = json_blockheader['stake_selector']

        return tmp

    def generate_headerhash(self):
        # FIXME: This is using strings... fix
        data = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}".format(self.stake_selector,
                                                       self.epoch,
                                                       self.block_reward,
                                                       self.fee_reward,
                                                       self.timestamp,
                                                       self.blocknumber,
                                                       self.prev_blockheaderhash,
                                                       self.tx_merkle_root,
                                                       self.reveal_hash)
        return sha2_256(str2bin(data))

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

