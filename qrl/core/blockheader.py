import decimal
from math import log

from qrl.core import ntp, logger, config
from qrl.crypto.misc import sha256


class BlockHeader(object):
    def __init__(self):
        # FIXME: init and create should probably be merged
        self.blocknumber = None
        self.hash = None
        self.timestamp = None
        self.prev_blockheaderhash = None
        self.tx_merkle_root = None
        self.reveal_list = None
        self.vote_hashes = None
        self.epoch = None
        self.stake_selector = None
        self.block_reward = None
        self.headerhash = None

    def create(self,
               chain,
               blocknumber,
               hashchain_link,
               prev_blockheaderhash,
               hashedtransactions,
               reveal_list,
               vote_hashes):
        """
        Create a block header based on the parameters
        :param chain:
        :param blocknumber:
        :param hashchain_link:
        :param prev_blockheaderhash:
        :param hashedtransactions:
        :param reveal_list:
        :param vote_hashes:
        :return:
        """

        self.blocknumber = blocknumber
        self.hash = hashchain_link

        if self.blocknumber == 0:
            self.timestamp = 0
        else:
            self.timestamp = ntp.getTime()
            if self.timestamp == 0:
                logger.warning('Failed to get NTP timestamp')
                return

        self.prev_blockheaderhash = prev_blockheaderhash
        self.tx_merkle_root = hashedtransactions
        self.reveal_list = reveal_list
        self.vote_hashes = vote_hashes
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
        rl = json_blockheader['reveal_list']
        self.reveal_list = []
        for r in rl:
            self.reveal_list.append(r.encode('latin1'))
        v1 = json_blockheader['vote_hashes']
        self.vote_hashes = []
        for v in v1:
            self.vote_hashes.append(v.encode('latin1'))
        self.epoch = json_blockheader['epoch']
        self.headerhash = json_blockheader['headerhash'].encode('latin1')
        self.hash = json_blockheader['hash'].encode('latin1')
        self.timestamp = json_blockheader['timestamp']
        self.tx_merkle_root = json_blockheader['tx_merkle_root'].encode('latin1')
        self.blocknumber = json_blockheader['blocknumber']
        self.prev_blockheaderhash = json_blockheader['prev_blockheaderhash'].encode('latin1')
        self.stake_selector = json_blockheader['stake_selector'].encode('latin1')
        self.block_reward = json_blockheader['block_reward']

    @staticmethod
    def calc_coeff(N_tot, block_tot):
        # TODO: This is more related to the way QRL works.. Move to another place
        """
        block reward calculation
        decay curve: 200 years (until 2217AD, 420480000 blocks at 15s block-times)
        N_tot is less the initial coin supply.
        :param N_tot:
        :param block_tot:
        :return:
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
        """
        coeff = BlockHeader.calc_coeff(21000000, 420480000)
        return decimal.Decimal(N_tot * decimal.Decimal(-coeff * block_n).exp()) \
            .quantize(decimal.Decimal('1.00000000'), rounding=decimal.ROUND_HALF_UP)

    def block_reward_calc(self):
        """
        return block reward for the block_n
        :return:
        """
        return int((BlockHeader.remaining_emission(21000000, self.blocknumber - 1)
                    - self.remaining_emission(21000000, self.blocknumber)) * 100000000)

    def generate_headerhash(self):
        # FIXME: This is using strings... fix
        return sha256(self.stake_selector +
                      str(self.epoch) +
                      str(self.block_reward) +
                      str(self.timestamp) +
                      str(self.hash) +
                      str(self.blocknumber) +
                      self.prev_blockheaderhash +
                      self.tx_merkle_root +
                      str(self.vote_hashes) +
                      str(self.reveal_list))
