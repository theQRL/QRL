# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import decimal
from math import log

import simplejson as json

import helper
import merkle
import ntp
import configuration as config
from merkle import sha256
from qrlcore import logger
from transaction import Transaction
import transaction

class BlockHeader(object):
    def create(self, chain, blocknumber, hashchain_link, prev_blockheaderhash, hashedtransactions, reveal_list,
               vote_hashes):
        self.blocknumber = blocknumber
        self.hash = hashchain_link
        if self.blocknumber == 0:
            self.timestamp = 0
        else:
            self.timestamp = ntp.getTime()
            if self.timestamp == 0:
                logger.info('Failed to get NTP timestamp')
                return
        self.prev_blockheaderhash = prev_blockheaderhash
        self.tx_merkle_root = hashedtransactions
        self.reveal_list = reveal_list
        self.vote_hashes = vote_hashes
        self.epoch = self.blocknumber // config.dev.blocks_per_epoch

        if self.blocknumber == 0:
            self.stake_selector = ''
            self.stake_nonce = 0
            self.block_reward = 0
        elif self.blocknumber == 1:
            tmp_chain, _ = chain.select_hashchain(
                last_block_headerhash=chain.block_chain_buffer.get_strongest_headerhash(0), hashchain=chain.hash_chain,
                blocknumber=self.blocknumber)
            self.stake_nonce = config.dev.blocks_per_epoch - tmp_chain.index(hashchain_link)
            self.stake_selector = chain.mining_address
            self.block_reward = self.block_reward_calc()
        else:
            for s in chain.block_chain_buffer.stake_list_get(self.blocknumber):
                if s[0] == chain.mining_address:
                    self.stake_nonce = s[2] + 1
            self.stake_selector = chain.mining_address
            self.block_reward = self.block_reward_calc()

        self.headerhash = self.generate_headerhash()

    def json_to_blockheader(self, json_blockheader):
        rl = json_blockheader['reveal_list']
        self.reveal_list = []
        for r in rl:
            self.reveal_list.append(r.encode('latin1'))
        v1 = json_blockheader['vote_hashes']
        self.vote_hashes = []
        for v in v1:
            self.vote_hashes.append(v.encode('latin1'))
        self.stake_nonce = json_blockheader['stake_nonce']
        self.epoch = json_blockheader['epoch']
        self.headerhash = json_blockheader['headerhash'].encode('latin1')
        self.hash = json_blockheader['hash'].encode('latin1')
        self.timestamp = json_blockheader['timestamp']
        self.tx_merkle_root = json_blockheader['tx_merkle_root'].encode('latin1')
        self.blocknumber = json_blockheader['blocknumber']
        self.prev_blockheaderhash = json_blockheader['prev_blockheaderhash'].encode('latin1')
        self.stake_selector = json_blockheader['stake_selector'].encode('latin1')
        self.block_reward = json_blockheader['block_reward']

    # block reward calculation
    # decay curve: 200 years (until 2217AD, 420480000 blocks at 15s block-times)
    # N_tot is less the initial coin supply.

    def calc_coeff(self, N_tot, block_tot):
        return log(N_tot) / block_tot

    # calculate remaining emission at block_n: N=total initial coin supply, coeff = decay constant
    # need to use decimal as floating point not precise enough on different platforms..

    def remaining_emission(self, N_tot, block_n):
        coeff = self.calc_coeff(21000000, 420480000)
        return decimal.Decimal(N_tot * decimal.Decimal(-coeff * block_n).exp()).quantize(decimal.Decimal('1.00000000'),
                                                                                         rounding=decimal.ROUND_HALF_UP)

    # return block reward for the block_n

    def block_reward_calc(self):
        return int((self.remaining_emission(21000000, self.blocknumber - 1) - self.remaining_emission(21000000,
                                                                 self.blocknumber)) * 100000000)

    def generate_headerhash(self):
        return sha256(self.stake_selector + str(self.epoch) + str(self.stake_nonce) + str(self.block_reward) + str(
            self.timestamp) + str(self.hash) + str(self.blocknumber) + self.prev_blockheaderhash +
            self.tx_merkle_root + str(self.vote_hashes) + str(self.reveal_list))

class Block(object):

    def isHashPresent(self, txhash, buffer, blocknumber):
        if not buffer:
            return False

        min_blocknum = min(buffer)
        max_blocknum = min(blocknumber - 1, max(buffer))

        for blocknum in xrange(min_blocknum, max_blocknum + 1):
            if txhash in buffer[blocknum]:
                return True

        return False

    def create(self, chain, hashchain_link, reveal_list=None, vote_hashes=None, last_block_number=-1):
        if not reveal_list:
            reveal_list = []
        if not vote_hashes:
            vote_hashes = []

        data = None
        if last_block_number == -1:
            data = chain.block_chain_buffer.get_last_block()  # m_get_last_block()
        else:
            data = chain.block_chain_buffer.get_block_n(last_block_number)

        last_block_number = data.blockheader.blocknumber
        prev_blockheaderhash = data.blockheader.headerhash

        hashedtransactions = []
        self.transactions = [None]

        for tx in chain.transaction_pool:
            hashedtransactions.append(tx.txhash)
            self.transactions.append(tx) # copy memory rather than sym link

        if not hashedtransactions:
            hashedtransactions = sha256('')

        hashedtransactions = chain.merkle_tx_hash(hashedtransactions)

        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain,
                                blocknumber=last_block_number + 1,
                                reveal_list=reveal_list,
                                vote_hashes=vote_hashes,
                                hashchain_link=hashchain_link,
                                prev_blockheaderhash=prev_blockheaderhash,
                                hashedtransactions=hashedtransactions)

        coinbase_tx = transaction.CoinBase().create(self.blockheader.block_reward, self.blockheader.headerhash, chain.my[0][1])
        self.transactions[0] = coinbase_tx
        coinbase_tx.nonce = chain.block_chain_buffer.get_stxn_state(last_block_number + 1, chain.mining_address)[0] + 1


    def json_to_block(self, json_block):
        self.blockheader = BlockHeader()
        self.blockheader.json_to_blockheader(json_block['blockheader'])

        transactions = json_block['transactions']
        self.transactions = []
        for tx in transactions:
            self.transactions.append(Transaction.get_tx_obj(tx))

        if self.blockheader.blocknumber == 0:
            self.state = json_block['state']
            self.stake_list = json_block['stake_list']

    @staticmethod
    def from_json(json_block):
        """
        Constructor a block from a json string
        :param json_block: a block serialized as a json string
        :return: A block
        """
        tmp_block = Block()
        tmp_block.json_to_block(json.loads(json_block))
        return tmp_block

    def validate_tx_in_block(self):
        #Validating coinbase txn
        coinbase_txn = self.transactions[0]
        valid = coinbase_txn.validate_tx(block_headerhash=self.blockheader.headerhash)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_num in xrange(1, len(self.transactions)):
            tx = self.transactions[tx_num]
            if tx.validate_tx() is False:
                logger.warning('invalid tx in block')
                logger.warning('subtype: %s txhash: %s txfrom: %s', tx.subtype, tx.txhash, tx.txfrom)
                return False

        return True

    # block validation

    def validate_block(self, chain, verify_block_reveal_list=True):  # check validity of new block..
        b = self.blockheader
        last_blocknum = b.blocknumber - 1

        if len(self.transactions) == 0:
            logger.warning('BLOCK : There must be atleast 1 txn')
            return False

        coinbase_tx = self.transactions[0]

        try:
            if coinbase_tx.subtype != transaction.TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False
        except Exception as e:
            logger.exception(e)
            return False

        if coinbase_tx.txfrom != self.blockheader.stake_selector:
            logger.info('Non matching txto and stake_selector')
            logger.info('txto: %s stake_selector %s', coinbase_tx.txfrom, self.blockheader.stake_selector)
            return False

        if coinbase_tx.amount != self.blockheader.block_reward:
            logger.info('Block_reward doesnt match')
            logger.info('Found: %d Expected: %d', coinbase_tx.amount, self.blockheader.block_reward)
            return False

        if b.timestamp == 0 and b.blocknumber > 0:
            logger.warning('Invalid block timestamp ')
            return False

        if b.block_reward != b.block_reward_calc():
            logger.warning('Block reward incorrect for block: failed validation')
            return False

        if b.epoch != b.blocknumber / config.dev.blocks_per_epoch:
            logger.warning('Epoch incorrect for block: failed validation')
            return False

        if b.blocknumber == 1:
            x = 0
            for tx in self.transactions:
                if tx.subtype == transaction.TX_SUBTYPE_STAKE:
                    if tx.txfrom == b.stake_selector:
                        x = 1
                        hash, _ = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash, b.stake_selector,
                                                         tx.hash, blocknumber=1)

                        if sha256(b.hash) != hash or hash not in tx.hash:
                            logger.warning('Hashchain_link does not hash correctly to terminator: failed validation')
                            return False
            if x != 1:
                logger.warning('Stake selector not in block.stake: failed validation')
                return False
        else:  # we look in stake_list for the hash terminator and hash to it..
            found = False
            terminator = sha256(b.hash)
            for _ in range(b.blocknumber - (b.epoch * config.dev.blocks_per_epoch) + 1):
                terminator = sha256(terminator)
            tmp_stake_list = chain.state.stake_list_get()
            for st in tmp_stake_list:
                if st[0] == b.stake_selector:
                    found = True

                    if terminator != st[1][-1]:
                        logger.warning('Supplied hash does not iterate to terminator: failed validation')
                        return False

            if not found:
                logger.warning('Stake selector not in stake_list for this epoch..')
                return False

            if len(b.reveal_list) != len(set(b.reveal_list)):
                logger.warning('Repetition in reveal_list')
                return False

            if verify_block_reveal_list:
                i = 0
                for r in b.reveal_list:
                    t = sha256(r)
                    for _ in range(b.blocknumber - (b.epoch * config.dev.blocks_per_epoch) + 1): # +1 as reveal has 1 extra hash
                        t = sha256(t)
                    for s in tmp_stake_list:
                        if t == s[1][-1]:
                            i += 1

                if i != len(b.reveal_list):
                    logger.warning('Not all the reveal_hashes are valid..')
                    return False

                i = 0
                target_chain = helper.select_target_hashchain(b.prev_blockheaderhash)
                for r in b.vote_hashes:
                    t = sha256(r)
                    for x in range(b.blocknumber - (b.epoch * config.dev.blocks_per_epoch)):
                        t = sha256(t)
                    for s in tmp_stake_list:
                        if t == s[1][target_chain]:
                            i += 1

                if i != len(b.vote_hashes):
                    logger.warning('Not all the reveal_hashes are valid..')
                    return False

        if b.generate_headerhash() != b.headerhash:
            logger.warning('Headerhash false for block: failed validation')
            return False

        tmp_last_block = chain.block_chain_buffer.get_block_n(last_blocknum)

        if tmp_last_block.blockheader.headerhash != b.prev_blockheaderhash:
            logger.warning('Headerhash not in sequence: failed validation')
            return False

        if tmp_last_block.blockheader.blocknumber != b.blocknumber - 1:
            logger.warning('Block numbers out of sequence: failed validation')
            return False

        if not self.validate_tx_in_block():
            logger.warning('Block validate_tx_in_block error: failed validation')
            return False

        if len(self.transactions) == 1:
            txhashes = sha256('')
        else:
            txhashes = []
            for tx_num in range(1,len(self.transactions)):
                tx = self.transactions[tx_num]
                txhashes.append(tx.txhash)

        if chain.merkle_tx_hash(txhashes) != b.tx_merkle_root:
            logger.warning('Block hashedtransactions error: failed validation')
            return False

        return True

    def validate_block_timestamp(self, last_block_timestamp):
        if last_block_timestamp >= self.blockheader.timestamp:
            return False
        curr_time = ntp.getTime()
        if curr_time == 0:
            return False

        max_block_number = int((curr_time - last_block_timestamp) / config.dev.block_creation_seconds)
        if self.blockheader.blocknumber > max_block_number:
            return False


