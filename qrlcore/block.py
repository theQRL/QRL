# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import decimal
from copy import deepcopy
from math import log

import configuration as c
import helper
import merkle
import ntp
from merkle import sha256
from qrlcore import logger
from transaction import StakeTransaction, SimpleTransaction


class BlockHeader(object):
    def create(self, chain, blocknumber, hashchain_link, prev_blockheaderhash, number_transactions, hashedtransactions,
               number_stake, hashedstake, reveal_list=None, vote_hashes=None, last_block_number=-1):
        if not reveal_list:
            reveal_list = []
        if not vote_hashes:
            vote_hashes = []
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
        self.number_transactions = number_transactions
        self.merkle_root_tx_hash = hashedtransactions
        self.number_stake = number_stake
        self.hashedstake = hashedstake
        self.reveal_list = reveal_list
        self.vote_hashes = vote_hashes
        self.epoch = self.blocknumber // c.blocks_per_epoch  # need to add in logic for epoch stake_list recalculation..

        if self.blocknumber == 0:
            self.stake_selector = ''
            self.stake_nonce = 0
            self.block_reward = 0
        elif self.blocknumber == 1:
            tmp_chain, _ = chain.select_hashchain(
                last_block_headerhash=chain.block_chain_buffer.get_strongest_headerhash(0), hashchain=chain.hash_chain,
                blocknumber=self.blocknumber)
            self.stake_nonce = c.blocks_per_epoch - tmp_chain.index(hashchain_link)
            self.stake_selector = chain.mining_address
            self.block_reward = self.block_reward_calc()
        else:
            for s in chain.block_chain_buffer.stake_list_get(self.blocknumber):
                if s[0] == chain.mining_address:
                    self.stake_nonce = s[2] + 1
            self.stake_selector = chain.mining_address
            self.block_reward = self.block_reward_calc()

        self.headerhash = sha256(
            self.stake_selector + str(self.epoch) + str(self.stake_nonce) + str(self.block_reward) + str(
                self.timestamp) + self.hash + str(self.blocknumber) + self.prev_blockheaderhash + str(
                self.number_transactions) + self.merkle_root_tx_hash + str(self.number_stake) + self.hashedstake)

        data = chain.my[0][1]
        S = data.SIGN(self.headerhash)
        self.i = S[0]
        self.signature = S[1]
        self.merkle_path = S[2]
        self.i_bms = S[3]
        self.pub = S[4]
        self.PK = S[5]

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
        self.number_transactions = json_blockheader['number_transactions']
        self.number_stake = json_blockheader['number_stake']
        self.hash = json_blockheader['hash'].encode('latin1')
        self.timestamp = json_blockheader['timestamp']
        self.merkle_root_tx_hash = json_blockheader['merkle_root_tx_hash'].encode('latin1')
        self.hashedstake = json_blockheader['hashedstake'].encode('latin1')
        self.blocknumber = json_blockheader['blocknumber']
        self.prev_blockheaderhash = json_blockheader['prev_blockheaderhash'].encode('latin1')
        self.stake_selector = json_blockheader['stake_selector'].encode('latin1')
        self.block_reward = json_blockheader['block_reward']
        self.i = json_blockheader['i']
        self.signature = json_blockheader['signature']
        self.merkle_path = json_blockheader['merkle_path']
        self.i_bms = json_blockheader['i_bms']
        self.pub = json_blockheader['pub']
        self.PK = json_blockheader['PK']

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


class Block(object):

    def isHashPresent(self, txhash, buffer, blocknumber):
        if not buffer:
            return False

        min_blocknum = min(buffer)
        max_blocknum = min(blocknumber - 1, max(buffer))

        for blocknum in xrange(min_blocknum, max_blocknum+1):
            if txhash in buffer[blocknum]:
                return True

        return False

    def create(self, chain, hashchain_link, reveal_list=None, vote_hashes=None, last_block_number=-1):
        # difficulty = 232
        if not reveal_list:
            reveal_list = []
        if not vote_hashes:
            vote_hashes = []

        data = None
        if last_block_number == -1:
            data = chain.block_chain_buffer.get_last_block()  # m_get_last_block()
        else:
            data = chain.block_chain_buffer.get_block_n(last_block_number)
        lastblocknumber = data.blockheader.blocknumber
        prev_blockheaderhash = data.blockheader.headerhash
        hashedtransactions = []
        for tx in chain.transaction_pool:
            if not chain.block_chain_buffer.pubhashExists(tx.txfrom, tx.pubhash, last_block_number + 1):
                if not self.isHashPresent(tx.txhash, chain.block_chain_buffer.tx_buffer, last_block_number + 1):
                    hashedtransactions.append(tx.txhash)
        if not hashedtransactions:
            hashedtransactions = sha256('')

        hashedtransactions = chain.merkle_tx_hash(hashedtransactions)
        self.transactions = []
        for tx in chain.transaction_pool:
            if not chain.block_chain_buffer.pubhashExists(tx.txfrom, tx.pubhash, last_block_number + 1):
                if not self.isHashPresent(tx.txhash, chain.block_chain_buffer.tx_buffer, last_block_number + 1):
                    self.transactions.append(tx)  # copy memory rather than sym link
        curr_epoch = int((last_block_number + 1) / c.blocks_per_epoch)

        self.stake = []
        if not chain.stake_pool:
            hashedstake = sha256('')
        else:
            sthashes = []
            for st in chain.stake_pool:
                if st.epoch != curr_epoch:
                    logger.info('Skipping st as epoch mismatch, CreateBlock()')
                    logger.info(('Expected st epoch : ', curr_epoch))
                    logger.info(('Found st epoch : ', st.epoch))
                    continue
                #if st.get_message_hash() not in chain.block_chain_buffer.st_buffer:
                '''
                if not self.isHashPresent(st.get_message_hash(), chain.block_chain_buffer.st_buffer, last_block_number + 1):
                    sthashes.append(str(st.hash))
                    self.stake.append(st)
                '''
                balance = 0
                for st2 in chain.block_chain_buffer.next_stake_list_get(lastblocknumber+1):
                    if st2[1] == st.hash:
                        balance = st2[-1]
                        break
                if balance>0 or lastblocknumber==0:
                    if st.first_hash:
                        new_st = deepcopy(st)
                        if lastblocknumber>0:
                            new_st.balance = balance
                        sthashes.append(str(new_st.hash))
                        self.stake.append(new_st)
                elif not st.first_hash:
                    sthashes.append(str(st.hash))
                    self.stake.append(st)

            hashedstake = sha256(''.join(sthashes))
        '''
        for st in chain.stake_pool:
            if st.epoch != curr_epoch:
                logger.info(('Skipping st as epoch mismatch, CreateBlock()'))
                logger.info(('Expected st epoch : ', curr_epoch))
                logger.info(('Found st epoch : ', st.epoch))
                continue

            #if st.get_message_hash() not in chain.block_chain_buffer.st_buffer:
            if not self.isHashPresent(st.get_message_hash(), chain.block_chain_buffer.st_buffer, last_block_number + 1):
                self.stake.append(st)
        '''
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain, blocknumber=lastblocknumber + 1, reveal_list=reveal_list, vote_hashes=vote_hashes,
                                hashchain_link=hashchain_link, prev_blockheaderhash=prev_blockheaderhash,
                                number_transactions=len(self.transactions), hashedtransactions=hashedtransactions,
                                number_stake=len(chain.stake_pool), hashedstake=hashedstake,
                                last_block_number=last_block_number)
        if self.blockheader.timestamp == 0:
            logger.info('Failed to create block due to timestamp 0')

    def json_to_block(self, json_block):
        self.blockheader = BlockHeader()
        self.blockheader.json_to_blockheader(json_block['blockheader'])

        transactions = json_block['transactions']
        self.transactions = []
        for tx in transactions:
            self.transactions.append(SimpleTransaction().dict_to_transaction(tx))

        stake = json_block['stake']
        self.stake = []
        if self.blockheader.blocknumber == 0:
            self.state = json_block['state']
            self.stake_list = json_block['stake_list']
        for st in stake:
            st_obj = StakeTransaction().dict_to_transaction(st)
            if st_obj.epoch != self.blockheader.epoch:
                continue
            self.stake.append(st_obj)

    def validate_tx_in_block(self):

        for transaction in self.transactions:
            if transaction.validate_tx() is False:
                logger.info(('invalid tx: ', transaction, 'in block'))
                return False

        return True

    def validate_st_in_block(self):

        for st in self.stake:
            if st.validate_tx() is False:
                logger.info(('invalid st:', st, 'in block'))
                return False

        return True

    # block validation

    def validate_block(self, chain, verbose=0, verify_block_reveal_list=True):  # check validity of new block..
        b = self.blockheader
        last_block = b.blocknumber - 1

        if merkle.xmss_verify(b.headerhash, [b.i, b.signature, b.merkle_path, b.i_bms, b.pub, b.PK]) is False:
            logger.info('BLOCK : merkle xmss_verify failed for the block')
            return False

        if helper.xmss_checkaddress(b.PK, b.stake_selector) is False:
            logger.info('BLOCK : xmss checkaddress failed')
            return False

        if b.timestamp == 0 and b.blocknumber > 0:
            logger.info('Invalid block timestamp ')
            return False

        if b.block_reward != b.block_reward_calc():
            logger.info('Block reward incorrect for block: failed validation')
            return False

        if b.epoch != b.blocknumber / c.blocks_per_epoch:
            logger.info('Epoch incorrect for block: failed validation')

        if b.blocknumber == 1:
            x = 0
            for st in self.stake:
                if st.txfrom == b.stake_selector:
                    x = 1
                    hash, _ = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash, b.stake_selector,
                                                     st.hash, blocknumber=1)

                    if sha256(b.hash) != hash or hash not in st.hash:
                        logger.info('Hashchain_link does not hash correctly to terminator: failed validation')
                        return False
            if x != 1:
                logger.info('Stake selector not in block.stake: failed validation')
                return False
        else:  # we look in stake_list for the hash terminator and hash to it..
            y = 0
            terminator = sha256(b.hash)
            for x in range(b.blocknumber - (b.epoch * c.blocks_per_epoch) + 1):
                terminator = sha256(terminator)
            tmp_stake_list = chain.state.stake_list_get()
            for st in tmp_stake_list:
                if st[0] == b.stake_selector:
                    y = 1

                    if terminator != st[1][-1]:
                        logger.info('Supplied hash does not iterate to terminator: failed validation')
                        return False

            if y != 1:
                logger.info('Stake selector not in stake_list for this epoch..')
                return False

            '''
                This condition not required, in case of a strongest block selected is not in top 3. 
                As it may happen that top 3 winners, didn't create the block, and other node created the block who was 
                not in the top 3 winners.
            '''
            #if b.hash not in chain.select_winners(b.reveal_list, topN=3, blocknumber=b.blocknumber, block=self, seed=chain.block_chain_buffer.get_epoch_seed(b.blocknumber)):
            #    logger.info(("Closest hash not in block selector.."))
            #    return False

            if len(b.reveal_list) != len(set(b.reveal_list)):
                logger.info('Repetition in reveal_list')
                return False

            if verify_block_reveal_list:

                i = 0
                for r in b.reveal_list:
                    t = sha256(r)
                    for x in range(b.blocknumber - (b.epoch * c.blocks_per_epoch) + 1): #+1 as reveal has 1 extra hash
                        t = sha256(t)
                    for s in tmp_stake_list:
                        if t == s[1][-1]:
                            i += 1

                if i != len(b.reveal_list):
                    logger.info('Not all the reveal_hashes are valid..')
                    return False

                i = 0
                target_chain = helper.select_target_hashchain(b.prev_blockheaderhash)
                for r in b.vote_hashes:
                    t = sha256(r)
                    for x in range(b.blocknumber - (b.epoch * c.blocks_per_epoch)):
                        t = sha256(t)
                    for s in tmp_stake_list:
                        if t == s[1][target_chain]:
                            i += 1

                if i != len(b.vote_hashes):
                    logger.info('Not all the reveal_hashes are valid..')
                    return False

        if sha256(b.stake_selector + str(b.epoch) + str(b.stake_nonce) + str(b.block_reward) + str(b.timestamp) + str(
                b.hash) + str(b.blocknumber) + b.prev_blockheaderhash + str(
                b.number_transactions) + b.merkle_root_tx_hash + str(b.number_stake) + b.hashedstake) != b.headerhash:
            logger.info('Headerhash false for block: failed validation')
            return False

        tmp_last_block = chain.m_get_block(last_block)

        if tmp_last_block.blockheader.headerhash != b.prev_blockheaderhash:
            logger.info('Headerhash not in sequence: failed validation')
            return False
        if tmp_last_block.blockheader.blocknumber != b.blocknumber - 1:
            logger.info('Block numbers out of sequence: failed validation')
            return False

        if self.validate_tx_in_block() == False:
            logger.info('Block validate_tx_in_block error: failed validation')
            return False

        if self.validate_st_in_block() == False:
            logger.info('Block validate_st_in_block error: failed validation')
            return False

        if len(self.transactions) == 0:
            txhashes = sha256('')
        else:
            txhashes = []
            for transaction in self.transactions:
                txhashes.append(transaction.txhash)

        if chain.merkle_tx_hash(txhashes) != b.merkle_root_tx_hash:
            logger.info('Block hashedtransactions error: failed validation')
            return False

        sthashes = []
        for st in self.stake:
            sthashes.append(str(st.hash))

        if sha256(''.join(sthashes)) != b.hashedstake:
            logger.info('Block hashedstake error: failed validation')

        if verbose == 1:
            logger.info((b.blocknumber, 'True'))

        return True

    def validate_block_timestamp(self, last_block_timestamp):
        if last_block_timestamp >= self.blockheader.timestamp:
            return False
        curr_time = ntp.getTime()
        if curr_time == 0:
            return False

        max_block_number = int((curr_time - last_block_timestamp) / c.block_creation_seconds)
        if self.blockheader.blocknumber > max_block_number:
            return False


