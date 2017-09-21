# coding=utf-8
import decimal
from math import log

from pyqrllib.pyqrllib import sha2_256, str2bin
from qrl.core import ntp, logger, config


class BlockHeader(object):
    def __init__(self):
        """
        >>> BlockHeader() is not None
        True
        """
        # FIXME: init and create should probably be merged
        self.blocknumber = None
        self.timestamp = None
        self.prev_blockheaderhash = None
        self.tx_merkle_root = None
        self.reveal_hash = None
        self.vote_hash = None
        self.epoch = None
        self.stake_selector = None
        self.block_reward = None
        self.headerhash = None
        self.fee_reward = 0

    def create(self,
               chain,
               blocknumber,
               prev_blockheaderhash,
               hashedtransactions,
               reveal_hash,
               vote_hash,
               fee_reward):
        """
        Create a block header based on the parameters
        :param chain:
        :param blocknumber:
        :param prev_blockheaderhash:
        :param hashedtransactions:
        :param reveal_hash:
        :param vote_hash:
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

        if self.blocknumber == 0:
            self.timestamp = 0
        else:
            self.timestamp = int(ntp.getTime())
            if self.timestamp == 0:
                logger.warning('Failed to get NTP timestamp')
                return

        self.prev_blockheaderhash = prev_blockheaderhash
        self.tx_merkle_root = hashedtransactions
        self.reveal_hash = reveal_hash
        self.vote_hash = vote_hash
        self.fee_reward = fee_reward
        self.epoch = self.blocknumber // config.dev.blocks_per_epoch

        if self.blocknumber == 0:
            self.stake_selector = ''
            self.block_reward = 0
        else:
            if self.blocknumber == 1:
                tmp_chain, _ = chain.select_hashchain(
                    last_block_headerhash=chain.block_chain_buffer.get_strongest_headerhash(0),
                    hashchain=chain.hash_chain,
                    blocknumber=self.blocknumber)
            self.stake_selector = chain.mining_address
            self.block_reward = self.block_reward_calc()

        self.headerhash = self.generate_headerhash()

    def json_to_blockheader(self, json_blockheader):
        # TODO: Moving to protobuf?
        self.reveal_hash = tuple(json_blockheader['reveal_hash'])
        self.vote_hash = tuple(json_blockheader['vote_hash'])
        self.epoch = json_blockheader['epoch']
        self.headerhash = tuple(json_blockheader['headerhash'])
        self.timestamp = json_blockheader['timestamp']
        self.tx_merkle_root = tuple(json_blockheader['tx_merkle_root'])
        self.blocknumber = json_blockheader['blocknumber']
        self.prev_blockheaderhash = tuple(json_blockheader['prev_blockheaderhash'])
        self.stake_selector = json_blockheader['stake_selector']
        self.block_reward = json_blockheader['block_reward']
        self.fee_reward = json_blockheader['fee_reward']

    @staticmethod
    def calc_coeff(N_tot, block_tot):
        # TODO: This is more related to the way QRL works.. Move to another place
        # TODO: Verify these values and formula
        """
        block reward calculation
        decay curve: 200 years (until 2217AD, 420480000 blocks at 15s block-times)
        N_tot is less the initial coin supply.
        :param N_tot:
        :param block_tot:
        :return:
        >>> BlockHeader.calc_coeff(1, 1)
        0.0
        """
        return log(N_tot) / block_tot

    @staticmethod
    def remaining_emission(N_tot, block_n):
        # TODO: This is more related to the way QRL works.. Move to another place
        """
        calculate remaining emission at block_n: N=total initial coin supply, coeff = decay constant
        need to use decimal as floating point not precise enough on different platforms..
        :param N_tot:
        :param block_n:
        :return:

        >>> BlockHeader.remaining_emission(1, 1)
        Decimal('0.99999996')
        """
        # TODO: Verify these values and formula
        coeff = BlockHeader.calc_coeff(config.dev.total_coin_supply, 420480000)
        return decimal.Decimal(N_tot * decimal.Decimal(-coeff * block_n).exp()) \
            .quantize(decimal.Decimal('1.00000000'), rounding=decimal.ROUND_HALF_UP)

    def block_reward_calc(self):
        """
        return block reward for the block_n
        :return:
        """
        return int((BlockHeader.remaining_emission(config.dev.total_coin_supply, self.blocknumber - 1)
                    - self.remaining_emission(config.dev.total_coin_supply, self.blocknumber)) * 100000000)

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
                                                       self.vote_hash,
                                                       self.reveal_hash)
        return sha2_256(str2bin(data))
