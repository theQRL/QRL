from merkle import sha256
import configuration as c
import helper
import ntp
from math import log
import decimal
import merkle
from transaction import StakeTransaction, SimpleTransaction
from copy import deepcopy

class BlockHeader():
    def create(self, chain, blocknumber, hashchain_link, prev_blockheaderhash, number_transactions, hashedtransactions,
               number_stake, hashedstake, reveal_list=None, vote_hashes=None, last_block_number=-1):
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
                printL(('Skipping st as epoch mismatch, CreateBlock()'))
                printL(('Expected st epoch : ', curr_epoch))
                printL(('Found st epoch : ', st.epoch))
                continue

            #if st.get_message_hash() not in chain.block_chain_buffer.st_buffer:
            if not self.isHashPresent(st.get_message_hash(), chain.block_chain_buffer.st_buffer, last_block_number + 1):
                self.stake.append(st)
        '''
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain, blocknumber=lastblocknumber + 1, reveal_list=reveal_list, vote_hashes=vote_hashes,
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
            if transaction.validate_tx() is False and self.blockheader.blocknumber>2900:
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

        max_block_number = int((curr_time - last_block_timestamp) / c.block_creation_seconds)
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
            ['Qde6bcd56bdf71beb1d0c549c9a39c9d167c37c351f8a4a6799998fa946f9ff7ba529', [0, 10000 * 100000000, []]],
            ['Q8659fc2ad3435d8a3b2e516301d523eef1502a40e4218e867e02c3af57ce561a5477', [0, 10000 * 100000000, []]],
            ['Q113618302254656b6a9262a4ab6e5b5ecf6a36f9e0c8869930fbbe16ca35fae17dd8', [0, 10000 * 100000000, []]],
            ['Q8e8b07be5db4b41108cab22ab4c5af846b1de9edef979f7e4a6cce90c9d3495bf33f', [0, 10000 * 100000000, []]],
            ['Q4a206b1b779295b255827d60a964eaf6abed9f4abd016081df3b76976c006a6d4220', [0, 10000 * 100000000, []]],
            ['Q532aab06486368989032914c646bdebcf944a413ac2891703cbc4b0fbbd414c77346', [0, 10000 * 100000000, []]],
            ['Qc6e43475408924f9c79fa2535a6999d44c1982dc9e7648ca76ad02378997d1818745', [0, 10000 * 100000000, []]],
            ['Q62436b3074a88e8759420bb3953012dbedd86508f8dd6abfa74d60348da65f6f4a10', [0, 10000 * 100000000, []]],
            ['Q787dc76c2ffd6c7af813fd836aa6911ff2f2abf836b384f9e047f4edf28ba51888c0', [0, 10000 * 100000000, []]],
            ['Qb19607ca2ff5df029a3362c296a77eb400c8f523152ba10f6cea0bd94ab118bdea87', [0, 10000 * 100000000, []]],
            ['Q180af39234f1862dd73ebc28291ca0926bc57d5a260908fbfef964164d44b06ff967', [0, 10000 * 100000000, []]],
            ['Qebf138a44f6d75ab817bff7e6a4a98d3e36ee5288e5668ed2d8ee1e420f7db231dda', [0, 10000 * 100000000, []]],
            ['Qf6d77eb8057d1ba7e77433dfb6b6e83bbd91e9229f705267edfd6b4955c4422d8dd2', [0, 10000 * 100000000, []]],
            ['Q57e188d50e4a014898c056df93915696f10c0d6cf69101d6f6c175a656543845b964', [0, 10000 * 100000000, []]],
            ['Qe8d86c4c84927010ebb0dca6f7b3cfa61aede13bbdab32b567e88962f84b08a8f70e', [0, 10000 * 100000000, []]],
            ['Qcd9969e22561b67f1e714e0b7d7ad6caf9221f936564904a9a35c676ef63aa166925', [0, 10000 * 100000000, []]],
            ['Q8b4a13eb1a4a5310cfea84215fc4aa4b7c76db4d561b18e8efe1eeef192207cc6992', [0, 10000 * 100000000, []]],
            ['Q94849edaa238694cff70f50d13c114b1436c9d7d1a8d23549987d078b46bb27aceae', [0, 10000 * 100000000, []]],
            ['Qcfb657b3786d03b4e801abdb86faaac3083ba0da88aab18b540cdbf68d81a8a01e8b', [0, 10000 * 100000000, []]],
            ['Qb89f3231f6de962b4e8216e70147e74f3e392d5fd2e409ad32298bcc992cf2132d85', [0, 10000 * 100000000, []]],
            ['Qffd70f44926adb81be6dc16012f448c19c0c40cbf74df701933ff5665fa030ba2d00', [0, 10000 * 100000000, []]],
            ['Q783ff91bbd02d75e84dfd8b9e5c73e3fb7d86db2404b4cf34cf2b9ecf8f66c43d025', [0, 10000 * 100000000, []]],
            ['Q54db8b23ab85faf3b20f7de2091692e9617466e347393efae1ba8019b7dfca2b7a61', [0, 10000 * 100000000, []]],
            ['Q117648a662bed7622f6b1b9531c330a207579c9f79e873585f192c8db1488afcaa86', [0, 10000 * 100000000, []]],
            ['Q48739e3252cecbbcfd9c85377b221a57c252d137a6069863afa197c0bfdbefd8ac6f', [0, 10000 * 100000000, []]],
            ['Q12a82b54833dcfd19f22f72a78d36fe73151924a79e1042d1005bb7a8a55939a0659', [0, 10000 * 100000000, []]],
            ['Q12bb71fd0e4411d745bba4cc267bc593a7247a67f39f89fba98399e582e4c1e674ff', [0, 10000 * 100000000, []]],
            ['Q541517c001c0214890a0f89761d0896e72043b816f4214a57e95d091171db6890f3d', [0, 10000 * 100000000, []]],
            ['Qefeb889a00efd3d9fc00320dccdb41c40bbede1fd74dd60056ff1cdb12879ff2eef0', [0, 10000 * 100000000, []]],
            ['Q43b86ffa78188b658b6309cb0683b0fc7cc7baf34960b6b8322361e1a4f4174c65ae', [0, 10000 * 100000000, []]],
            ['Q39c3c2362b985ce8c6401074ac1826f0faeef8c94523af8e98c0693eadc84091b7e8', [0, 10000 * 100000000, []]],
            ['Qe54a87c98bc5364a617dacc9f0fbc4dc8da14a0fa0874ddcde723d7f072582fca59d', [0, 10000 * 100000000, []]],
            ['Q394c03f2668ee505d5f030176617127e7e2f483745b86686e7a76e2d396747ae9311', [0, 10000 * 100000000, []]],
            ['Qcbf8e928d41482266278ad19aa063614f99b1a1f589f3c6e83a827ff89eb07daffbe', [0, 10000 * 100000000, []]],
            ['Q01122e6d641140a6f5810dbe6db72555090778edd73c6ca1152efc4083b81b44c6ba', [0, 10000 * 100000000, []]],
            ['Qfc1a589516e19b2491d87e1552333e8e60c1c6c6ce981e5487a39a37f40dfb9a7225', [0, 10000 * 100000000, []]],
            ['Q7b0559c169df6d56aa066827460d6f9c44e0ab3e2618af132edc5aff8acdf24718b7', [0, 10000 * 100000000, []]],
            ['Q5e4f7622af2698f42ac285fc73df03ab2a245d97da39f52004d064074d929b6b649a', [0, 10000 * 100000000, []]],
            ['Qe8ab8d40bc1dbf78faca27ab8a779df853832b940bc19b5592747d90b5527dff4af1', [0, 10000 * 100000000, []]],
            ['Q3c80dbb7781b10c14112e36461e2fc1f0164af8c9fc61782f1fe4380b3547e17c246', [0, 10000 * 100000000, []]],
            ['Qe7ecbde482af1fc396abd85d159f4475f611a88e1e273ef473068e5fc4bf695b0098', [0, 10000 * 100000000, []]],
            ['Qc11291edff2bb76b7300913a32e864275cc163054acb0cd7205f56164c1b906385f2', [0, 10000 * 100000000, []]],
            ['Qd72878f770ba44130f118812e1251139298135afaf70a0f23037654469745a14c704', [0, 10000 * 100000000, []]],
            ['Q36bd511446e627f4eb21dc1b2679bf5709b85ec12a898cb73ba427c14a71a74ed50d', [0, 10000 * 100000000, []]],
            ['Q0426347c2bb63f9c59c883844a5c84ac26bf3e15ac5bf01efb1c95d72b2d80b4bb30', [0, 10000 * 100000000, []]],
            ['Qcba2b6cb59dcef23d16630c63071c2f814b3c9874b91d1dd023268e729dcd7000f85', [0, 10000 * 100000000, []]],
            ['Qb9b05156b4ae5605e8a452c5099c6fd4b7c4dc3dc5275921a3cb592d5658e83f2f55', [0, 10000 * 100000000, []]],
            ['Q929112d6f98456d88f388001be81d4234c03298cbdfea5ea1795f145187903890e7f', [0, 10000 * 100000000, []]],
            ['Q08934bc111aa0c578ec731d74adfd4b0466dfc4f69134e681ce5fd376c6b733c8aef', [0, 10000 * 100000000, []]],
            ['Q7130ca5571c1b661483231fc88533398164259fe6b95bcf208aae2291b52f07ebb51', [0, 10000 * 100000000, []]],
            ['Q5b0d39ba086f418c3f78e5d008c6f0834f3156d25c5486e8c609d4437bc3467c6596', [0, 10000 * 100000000, []]],
            ['Q49f5652e89587b57d0c2f531175224a02e441ceb58d7e4dc52b2a6a8651b2e2805ee', [0, 10000 * 100000000, []]],
            ['Qccf5d481aec3cdbdf4e068896577c92b83740efae2cca503680f592677df18e456dd', [0, 10000 * 100000000, []]],
            ['Q25751e679d2a2182c0e538b5f2ac2ade1f04e07555c5614392284920722847423a22', [0, 10000 * 100000000, []]],
            ['Q21c3b2e05703c48c28da192dd3cc469b4393390d78bb635a6de42359f60cb52a54ef', [0, 10000 * 100000000, []]],
            ['Q9cd4f6206a8b9f324facd7d7a785585b3034699350068bc6dc738fc7b3048cbedcd1', [0, 10000 * 100000000, []]],
            ['Q1c787c28b8945e0321e0fd0daeb756aeabde8ab8290e90d65f336f1975c80344ab5b', [0, 10000 * 100000000, []]],
            ['Qb6cef8d93b57240ade9659853c1df2af5f7c67a019efa60033ccccc7e2e5d4bc7765', [0, 10000 * 100000000, []]],
            ['Qf4762d711f83e946393221b8db7191d03493c280fd26c8a30adf8092865f436cafbb', [0, 10000 * 100000000, []]],
            ['Qa78735822eb377d206f2cc40ca0aceb23cb14b9f174fa8d954b0c074b49899c908cc', [0, 10000 * 100000000, []]],
            ['Q1a7ed3e83de595b0fc89376b4ea67ceff73203a26ac723bd39ed4ee07cad29519a7e', [0, 10000 * 100000000, []]],
            ['Q568b010953b13b6052cd21434d09baa30127ebbc51ab6d0d26df0df69e581c91a1a4', [0, 10000 * 100000000, []]],
            ['Qb0709c0442ef7a839b92e6b9e114bef5420a7921d02019289c4e156711976039e83c', [0, 10000 * 100000000, []]],
            ['Qb278a8c9cb396ce36de75a382dbd2a815a09fa6effb7567073f1e9022db71684e40d', [0, 10000 * 100000000, []]],
            ['Q3aa5bd989eecdcfdf115d962ded4f13f93c1853120acc6dc3b8c7766b9868ca2f3e4', [0, 10000 * 100000000, []]],
            ['Q73a4bea5aa9c53a462e2cd877fa09580b737ebce82cb9981d8ae98532b35ab47b629', [0, 10000 * 100000000, []]],
            ['Q853191d784cc0beac92b3f4544bd291092d05cf637839b2e2b9f60219823f3d0a4ac', [0, 10000 * 100000000, []]],
            ['Q2f9dd2dad7f62049e3bf6b5821546190d5da3b0098bd37f260209e066e84e6660d65', [0, 10000 * 100000000, []]],
            ['Q763532e386edd4a09a4293598fac90d3c40efd5a7790be289f908c9449368b3aeab7', [0, 10000 * 100000000, []]],
            ['Q06c3963ed6e21571afca46a8fe4b626f9ff6c21c56709d0a8776af91e15fae80da61', [0, 10000 * 100000000, []]],
            ['Qb6c0e03ac000a6e53448ad520f6a2e093a413f09c902d68d2a144e0a1a97148ad2ae', [0, 10000 * 100000000, []]],
            ['Q3ce9b050d9e6d3f6066721ef23d7c390583ac97882b194400762c3e9f0b68607e280', [0, 10000 * 100000000, []]],
            ['Q3abc67b82f781dff55b96d2d23d0ed0700936f773c543e93a238f6b87aebffb2a881', [0, 10000 * 100000000, []]],
            ['Qb11ea82ce380a253e9782d97bcf5d24eb823b48ef2f9d219c0ec66f33dbf09292581', [0, 10000 * 100000000, []]],
            ['Q6b58edfe3088b8f0ef4c718dd422b71f5a488704a2208d72949f05d83af699d96fb1', [0, 10000 * 100000000, []]],
            ['Qf6af2486558d3d6854c93772afbe2f3e859783f2ba096d3f8dff0e8c038f54d0afc9', [0, 10000 * 100000000, []]],
            ['Q33bf9c197ac0bb0e66302243fbddabb09f1f26081e247def2b43359a5ffc8790453d', [0, 10000 * 100000000, []]],
            ['Q529f0df008ab7b95a573e3b65ee150c60057af5245213c1709468a7719b8c9ffc02a', [0, 10000 * 100000000, []]],
            ['Qacb823ca7e9691955b30ba179bd47d39c98b322318776698b1c49f3194b5c3256844', [0, 10000 * 100000000, []]],
            ['Qdb3736c5f181f0319236684b20a9f399344208542ecd1f5717a9eaa367dd10f71da4', [0, 10000 * 100000000, []]],
            ['Q63277a8c929c7f37e4024da51f2cf986fa5eec81de0abfb8eecbe657c5e095adf17d', [0, 10000 * 100000000, []]],
            ['Q085b65444bd11e9f5d6395a84c54cc1e1b8b086622f3e29a18748eced66558242be0', [0, 10000 * 100000000, []]],
            ['Q6848a8a93cea7364c61ea135c49e5c450ddbc5f1d8f8b8621604874fdae66502c96a', [0, 10000 * 100000000, []]],
            ['Qcadb430b742015090abcfd5a704a4c67a57d87dc6139c2259a33b09fd7d294ed8a02', [0, 10000 * 100000000, []]],
            ['Q41e7c4395c2fba311c7c7b7b70580bfe1d2f2efb765404f1e3266fa540ecc9469645', [0, 10000 * 100000000, []]],
            ['Q3e28369f7eff6f739fc927ea84e8ab0f839c6122a35b7939cc0b4e556729cad8d3dd', [0, 10000 * 100000000, []]],
            ['Q74c77d1897519847f0ee35861241829a4a380c7476ea84e50b1737eb0fcc002ddfdf', [0, 10000 * 100000000, []]],
            ['Qf9f3dd8169a87b8607dbf89b145b540108a3a27ce6e60e7850ef751637d85fcbbd36', [0, 10000 * 100000000, []]],
            ['Qac74ea2e0f2f4b0d3897c629f84187c76e24c0aac2873ec3aa9adce2bc514c72a688', [0, 10000 * 100000000, []]],
            ['Q510e4b1dcd62a378768e23fb5576dcc67fa83de9a552ea5106e1d660525dedbf21a7', [0, 10000 * 100000000, []]],
            ['Qa9270d9d91ab67339dc99ab174a900ff3df49d657c0cc40c99687c1c022d91b9ec9f', [0, 10000 * 100000000, []]],
            ['Q3c4528d54ea487468a0c14969eb2a8c31d38937e84bd3019d7f5b6bf37ac8bf61835', [0, 10000 * 100000000, []]],
            ['Q963cdee3767e2f9ad517bae3524137f312ee75e3f8243836fa87781e5d16cf15f684', [0, 10000 * 100000000, []]],
            ['Q7e0c925bc38f694382580a5acc05526493f787ee21ef9313d0fe2013d988ff7af966', [0, 10000 * 100000000, []]],
            ['Q449dcb333d2d6aa4e385f5fe438555500ef0ae10e2c399749f8e0cb761a27d1b78fa', [0, 10000 * 100000000, []]],
            ['Q1881fd0be69cfb28ca6c87dd3bf37bb06d9c31db536e9fecf006daa519fe41038b28', [0, 10000 * 100000000, []]],
            ['Q9ad66195f6bfdeb1fbc6f2f11a96e5dfe34d0685d891a3808f136af99828e5821535', [0, 10000 * 100000000, []]],
            ['Q90cbc017bcf489ce67aefe82d84f468f83d1f1b0a88bd584eb5cd51ac24e92e589a4', [0, 10000 * 100000000, []]],
            ['Q7c9ee6b090173a411402cf5ae0f38c344d2ea922e809581fd02cf75b4f8fbc25ec15', [0, 10000 * 100000000, []]],
            ['Q09746364bd83198e9a0072fd7d2198e2becc0732de26b3adbee057881d4fd3cb520b', [0, 10000 * 100000000, []]],
            ['Qe3b6d83dce0e46aea8b9bf0df02f16de476ffbc9e8418861d76b34509bea3cfc4c3b', [0, 10000 * 100000000, []]],
            ['Q3b83bf853fc7ee57d8412430cf76d42661984af7b1ad9ca83d663a6e1dc49ebef865', [0, 10000 * 100000000, []]],
            ['Q059e4f3d15961b801c6856b9fae5bff11dab2f0ebc4252b71bbfcc7c796ee5f1bcb8', [0, 10000 * 100000000, []]],
            ['Q4b062c79aa74bc997b408b22fbf6f78fbe924502b759834cd60adea3c632c89d2bef', [0, 10000 * 100000000, []]],
            ['Qf434b9e1247fab025e81ad2e0c316bc4b150eba722f4b6ef72dc8ae0dbb1d149e4af', [0, 10000 * 100000000, []]],
        ]

        self.stake_list = []
        for stake in self.state:
            self.stake_list.append(stake[0])

        self.stake_seed = '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'
