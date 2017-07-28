from merkle import sha256
import configuration as c
import helper
import ntp
from math import log
import decimal
import merkle
from transaction import StakeTransaction, SimpleTransaction


class BlockHeader():
    def create(self, chain, blocknumber, hashchain_link, prev_blockheaderhash, number_transactions, hashedtransactions,
               number_stake, hashedstake, reveal_list=[], last_block_number=-1):
        self.blocknumber = blocknumber
        self.hash = hashchain_link
        if self.blocknumber == 0:
            self.timestamp = 0
        else:
            self.timestamp = ntp.getTime()
            if self.timestamp == 0:
                printL(('Failed to get NTP timestamp'))
                return
        self.prev_blockheaderhash = prev_blockheaderhash
        self.number_transactions = number_transactions
        self.merkle_root_tx_hash = hashedtransactions
        self.number_stake = number_stake
        self.hashedstake = hashedstake
        self.reveal_list = reveal_list
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


class Block():

    def isHashPresent(self, txhash, buffer, blocknumber):
        if not buffer:
            return False

        min_blocknum = min(buffer)
        max_blocknum = min(blocknumber - 1, max(buffer))

        for blocknum in xrange(min_blocknum, max_blocknum+1):
            if txhash in buffer[blocknum]:
                return True

        return False

    def create(self, chain, hashchain_link, reveal_list=None, last_block_number=-1):
        # difficulty = 232
        if not reveal_list:
            reveal_list = []

        data = None
        if last_block_number == -1:
            data = chain.block_chain_buffer.get_last_block()  # m_get_last_block()
        else:
            data = chain.block_chain_buffer.get_block_n(last_block_number)
        lastblocknumber = data.blockheader.blocknumber
        prev_blockheaderhash = data.blockheader.headerhash
        hashedtransactions = []
        for transaction in chain.transaction_pool:
            # if transaction.txhash not in chain.block_chain_buffer.tx_buffer:
            if not self.isHashPresent(transaction.txhash, chain.block_chain_buffer.tx_buffer, last_block_number + 1):
                hashedtransactions.append(transaction.txhash)
        if not hashedtransactions:
            hashedtransactions = sha256('')

        hashedtransactions = chain.merkle_tx_hash(hashedtransactions)
        self.transactions = []
        for tx in chain.transaction_pool:
            # if tx.txhash not in chain.block_chain_buffer.tx_buffer:
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
                    printL(('Skipping st as epoch mismatch, CreateBlock()'))
                    printL(('Expected st epoch : ', curr_epoch))
                    printL(('Found st epoch : ', st.epoch))
                    continue
                #if st.get_message_hash() not in chain.block_chain_buffer.st_buffer:
                if not self.isHashPresent(st.get_message_hash(), chain.block_chain_buffer.st_buffer, last_block_number + 1):
                    sthashes.append(str(st.hash))
                    self.stake.append(st)

            hashedstake = sha256(''.join(sthashes))
        '''
        for st in chain.stake_pool:
            if st.epoch != curr_epoch:
                printL(('Skipping st as epoch mismatch, CreateBlock()'))
                printL(('Expected st epoch : ', curr_epoch))
                printL(('Found st epoch : ', st.epoch))
                continue

            #if st.get_message_hash() not in chain.block_chain_buffer.st_buffer:
            if not self.isHashPresent(st.get_message_hash(), chain.block_chain_buffer.st_buffer, last_block_number + 1):
                self.stake.append(st)
        '''
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain, blocknumber=lastblocknumber + 1, reveal_list=reveal_list,
                                hashchain_link=hashchain_link, prev_blockheaderhash=prev_blockheaderhash,
                                number_transactions=len(chain.transaction_pool), hashedtransactions=hashedtransactions,
                                number_stake=len(chain.stake_pool), hashedstake=hashedstake,
                                last_block_number=last_block_number)
        if self.blockheader.timestamp == 0:
            printL(('Failed to create block due to timestamp 0'))

    def json_to_block(self, json_block):
        self.blockheader = BlockHeader()
        self.blockheader.json_to_blockheader(json_block['blockheader'])

        transactions = json_block['transactions']
        self.transactions = []
        for tx in transactions:
            self.transactions.append(SimpleTransaction().dict_to_transaction(tx))

        stake = json_block['stake']
        self.stake = []

        for st in stake:
            st_obj = StakeTransaction().dict_to_transaction(st)
            if st_obj.epoch != self.blockheader.epoch:
                continue
            self.stake.append(st_obj)

    def validate_tx_in_block(self):

        for transaction in self.transactions:
            if transaction.validate_tx() is False:
                printL(('invalid tx: ', transaction, 'in block'))
                return False

        return True

    def validate_st_in_block(self):

        for st in self.stake:
            if st.validate_tx() is False:
                printL(('invalid st:', st, 'in block'))
                return False

        return True

    # block validation

    def validate_block(self, chain, verbose=0, verify_block_reveal_list=True):  # check validity of new block..
        b = self.blockheader
        last_block = b.blocknumber - 1

        if merkle.xmss_verify(b.headerhash, [b.i, b.signature, b.merkle_path, b.i_bms, b.pub, b.PK]) is False:
            printL(('BLOCK : merkle xmss_verify failed for the block'))
            return False

        if helper.xmss_checkaddress(b.PK, b.stake_selector) is False:
            printL(('BLOCK : xmss checkaddress failed'))
            return False

        if b.timestamp == 0 and b.blocknumber > 0:
            printL(('Invalid block timestamp '))
            return False

        if b.block_reward != b.block_reward_calc():
            printL(('Block reward incorrect for block: failed validation'))
            return False

        if b.epoch != b.blocknumber / c.blocks_per_epoch:
            printL(('Epoch incorrect for block: failed validation'))

        if b.blocknumber == 1:
            x = 0
            for st in self.stake:
                if st.txfrom == b.stake_selector:
                    x = 1
                    hash, _ = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash, b.stake_selector,
                                                     st.hash, blocknumber=1)

                    if sha256(b.hash) != hash or hash not in st.hash:
                        printL(('Hashchain_link does not hash correctly to terminator: failed validation'))
                        return False
            if x != 1:
                printL(('Stake selector not in block.stake: failed validation'))
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
                    #hash, _ = chain.select_hashchain(chain.block_chain_buffer.get_strongest_headerhash(last_block),
                    #                                 b.stake_selector, blocknumber=b.blocknumber)

                    if terminator != st[1][-1]:
                        printL(('Supplied hash does not iterate to terminator: failed validation'))
                        return False
            if y != 1:
                printL(('Stake selector not in stake_list for this epoch..'))
                return False


            if b.hash not in chain.select_winners(b.reveal_list, topN=3, blocknumber=b.blocknumber, block=self, seed=chain.block_chain_buffer.get_epoch_seed(b.blocknumber)):
                printL(("Closest hash not in block selector.."))
                return False

            if len(b.reveal_list) != len(set(b.reveal_list)):
                printL(('Repetition in reveal_list'))
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
                    printL(('Not all the reveal_hashes are valid..'))
                    return False

        if sha256(b.stake_selector + str(b.epoch) + str(b.stake_nonce) + str(b.block_reward) + str(b.timestamp) + str(
                b.hash) + str(b.blocknumber) + b.prev_blockheaderhash + str(
                b.number_transactions) + b.merkle_root_tx_hash + str(b.number_stake) + b.hashedstake) != b.headerhash:
            printL(('Headerhash false for block: failed validation'))
            return False

        tmp_last_block = chain.m_get_block(last_block)

        if tmp_last_block.blockheader.headerhash != b.prev_blockheaderhash:
            printL(('Headerhash not in sequence: failed validation'))
            return False
        if tmp_last_block.blockheader.blocknumber != b.blocknumber - 1:
            printL(('Block numbers out of sequence: failed validation'))
            return False

        if self.validate_tx_in_block() == False:
            printL(('Block validate_tx_in_block error: failed validation'))
            return False

        if self.validate_st_in_block() == False:
            printL(('Block validate_st_in_block error: failed validation'))
            return False

        if len(self.transactions) == 0:
            txhashes = sha256('')
        else:
            txhashes = []
            for transaction in self.transactions:
                txhashes.append(transaction.txhash)

        if chain.merkle_tx_hash(txhashes) != b.merkle_root_tx_hash:
            printL(('Block hashedtransactions error: failed validation'))
            return False

        sthashes = []
        for st in self.stake:
            sthashes.append(str(st.hash))

        if sha256(''.join(sthashes)) != b.hashedstake:
            printL(('Block hashedstake error: failed validation'))

        if verbose == 1:
            printL((b.blocknumber, 'True'))

        return True

    def validate_block_timestamp(self, last_block_timestamp):
        if last_block_timestamp >= self.blockheader.timestamp:
            return False
        curr_time = ntp.getTime()
        if curr_time == 0:
            return False

        max_block_number = int((curr_time - last_block_timestamp) / c.block_creation_second)
        if self.blockheader.blocknumber > max_block_number:
            return False


class CreateGenesisBlock():  # first block has no previous header to reference..
    def __init__(self, chain):
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain, blocknumber=0, hashchain_link='genesis',
                                prev_blockheaderhash=sha256('quantum resistant ledger'), number_transactions=0,
                                hashedtransactions=sha256('0'), number_stake=0, hashedstake=sha256('0'))
        self.transactions = []
        self.stake = []
        self.state = [
            ['Q1cd0007a3c2f78ee535d10a267c43652fdd39acc833d35955d7bf1347a3f9f7bd8b9', [0, 10000 * 100000000, []]],
            ['Q9cfcf704f5eed6387486b68749c039cf3cdfd499cc58303e06e432dedc1cb3943f50', [0, 10000 * 100000000, []]],
            ['Q5c9cbdaf90a9a15c0a6937573ed7b3d57d226658ced86c03ec8fbd4639567721d4da', [0, 10000 * 100000000,
                                                                                       []]]]  # , ['Q34eabf7ef2c6582096a433237a603b862fd5a70ac4efe4fd69faae21ca390512b3ac', [0, 10000*100000000,[]]], ['Qfc6a9b751915048a7888b65e77f9a248379d8b47c94081b3baced7c1234dc7f4b419', [0, 10000*100000000,[]]] ]

        self.stake_list = []
        for stake in self.state:
            self.stake_list.append(stake[0])

        self.stake_seed = '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'
