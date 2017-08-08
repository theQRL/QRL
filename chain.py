# QRL main blockchain, state, stake, transaction functions.

# todo:
# pos_block_pool() should return all combinations, not just the order received then sorted by txhash - removes edge cases for block selection failure..
# add stake list check to the state check - addresses which are staking cannot make transactions..
# block-reward calculation to be altered based upon block-time and stake_list_get() balances..proportion of entire coin supply..
# fees
# occasionally the ots index gets behind..find reason..
# add salt/key xor to hash chains..

__author__ = 'pete'

import gc
import configuration as c
if c.compression_type == 'bz2':
    import bz2 as zip
else:
    import zlib as zip
from StringIO import StringIO
from time import time, sleep
from operator import itemgetter, attrgetter
from math import log, ceil
import heapq

import os, copy, ast, sys, jsonpickle
from copy import deepcopy
import simplejson as json
from collections import defaultdict

import cPickle as pickle


import wallet
from block import CreateGenesisBlock
import merkle
from merkle import sha256
import helper
from block import Block
from transaction import SimpleTransaction
from decimal import Decimal

class Chain:
    def __init__(self, state):
        self.state = state
        self.version_number = c.version_number  
        self.transaction_pool = []
        self.stake_pool = []
        self.txhash_timestamp = []
        self.m_blockchain = []
        self.wallet = wallet.Wallet(self, state)
        self.my = self.wallet.f_read_wallet()
        self.mining_address = self.my[0][1].address
        self.initialize()
        self.ping_list = []
        self.ip_list = []
        self.blockheight_map = []
        self.stake_list = []
        self.stake_commit = []
        self.block_chain_buffer = None  # Initialized by node.py
        self.prev_txpool = [None] * 1000  # TODO: use python dequeue
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = []
        self.stake_reveal_one = []
        self.stake_ban_list = []
        self.stake_ban_block = {}
        # self.epoch_prf = []
        # self.epoch_PRF = []
        self.stake_validator_latency = defaultdict(dict)

    def initialize(self):
        printL(('QRL blockchain ledger ', self.version_number))
        printL(('loading db'))
        printL(('loading wallet'))

        self.wallet.f_load_winfo()

        printL(('mining/staking address', self.mining_address))

    def validate_reboot(self, hash, nonce):
        reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]
        try:
            reboot_data_db = self.state.db.get('reboot_data')
            reboot_data = reboot_data_db
        except:
            pass

        if reboot_data[1] >= nonce:  # already used
            msg = 'nonce in db '+str(reboot_data[1])
            msg += '\nnonce provided '+str(nonce)
            return None, msg

        reboot_data[1] = nonce
        output = hash
        for i in range(0, reboot_data[1]):
            output = sha256(output)

        if output != reboot_data[0]:
            msg = 'expected hash '+str(reboot_data[0])
            msg += '\nhash found '+str(output)
            msg += '\nnonce provided '+str(nonce)+"\n"
            return None, msg
        #reboot_data[1] += 1
        #self.state.db.put('reboot_data', reboot_data)

        return True, 'Success'

    def generate_reboot_hash(self, key, nonce=None, blocknumber=0):
        reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]

        try:
            reboot_data = self.state.db.get('reboot_data')
        except:
            pass
        if nonce:
            if reboot_data[1] > nonce:
                return None, 'Nonce must be greater than or equals to ' + str(reboot_data[1]) + '\r\n'
            reboot_data[1] = int(nonce)

        output = sha256(key)
        for i in range(0, 40000 - reboot_data[1]):
            output = sha256(output)

        status, error = self.validate_reboot(output, reboot_data[1])
        if not status:
            return None, error

        return json.dumps({'hash': output, 'nonce': reboot_data[1], 'blocknumber': int(blocknumber)}), "Reboot Initiated\r\n"

    def get_sv(self, terminator):
        for s in self.state.stake_list_get():
            if terminator in s[1]:
                return s[0]

        return None

    def reveal_to_terminator(self, reveal, blocknumber, add_loop=0):
        tmp = sha256(reveal)
        epoch = blocknumber // c.blocks_per_epoch
        for x in range(blocknumber - (epoch * c.blocks_per_epoch) + add_loop):
            tmp = sha256(tmp)
        return tmp

    def select_hashchain(self, last_block_headerhash, stake_address=None, hashchain=None, blocknumber=None):

        if not hashchain:
            for s in self.block_chain_buffer.stake_list_get(blocknumber):
                if s[0] == stake_address:
                    hashchain = s[1]
                    break

        if not hashchain:
            return

        target_chain = 0
        for byte in last_block_headerhash:
            target_chain += ord(byte)

        target_chain = (target_chain - 1) % (c.hashchain_nums - 1)  # 1 Primary hashchain size

        return hashchain[-1], hashchain[target_chain]

    def select_winners(self, reveals, topN=1, blocknumber=None, block=None, seed=None):
        winners = None
        if not seed:
            printL (( 'Exception raised due to Seed is None'))
            raise Exception
        if blocknumber:
            winners = heapq.nsmallest(topN, reveals, key=lambda reveal: self.score(
                stake_address=self.get_sv(self.reveal_to_terminator(reveal, blocknumber, add_loop=1)),
                reveal_one=reveal,
                balance=self.block_chain_buffer.get_st_balance(self.get_sv(self.reveal_to_terminator(reveal, blocknumber, add_loop=1)), blocknumber),
                seed=seed))  #blocknumber+1 as we have one extra hash for the reveal
            return winners

        winners = heapq.nsmallest(topN, reveals, key=lambda reveal: reveal[4])  # reveal[4] is score
        winners_dict = {}
        for winner in winners:
            winners_dict[winner[3]] = winner  # winner[3] is reveal_one
        return winners_dict

    # def score(self, stake_address, reveal_one, block_reward=0, blocknumber=None, block=None, seed=None):
    def score(self, stake_address, reveal_one, balance=0, seed=None, verbose=False):
        if not seed:
            printL (( 'Exception Raised due to seed none in score fn'))
            raise Exception
        #balance = self.state.state_balance(stake_address)
        if not balance:
            printL((' balance 0 so score none '))
            printL((' stake_address ', stake_address))
            return None

        reveal_one_number = int(reveal_one, 16)
        #epoch_seed = self.block_chain_buffer.get_epoch_seed(blocknumber)

        score = (Decimal(c.N) - (Decimal(reveal_one_number | seed).log10()/Decimal(2).log10())) / Decimal(balance)
        if verbose:
            printL (( 'Score - ', score))
            printL (( 'reveal_one - ', reveal_one_number))
            printL (( 'seed - ', seed ))
            printL (( 'balance - ', balance ))
        return score

    def update_pending_tx_pool(self, tx, peer):
        if len(self.pending_tx_pool) >= c.blocks_per_epoch:
            del self.pending_tx_pool[0]
            del self.pending_tx_pool_hash[0]
        self.pending_tx_pool.append([tx, peer])
        self.pending_tx_pool_hash.append(tx.txhash)

    def get_stake_validators_hash(self):
        sv_hash = StringIO()
        stakers = self.state.stake_list_get()
        for staker in stakers:
            balance = self.state.state_balance(staker[0])
            sv_hash.write(staker[0] + str(balance))
        sv_hash = sha256(sv_hash.getvalue())
        return sv_hash

    # create a block from a list of supplied tx_hashes, check state to ensure validity..

    def create_stake_block(self, tx_hash_list, hashchain_hash, reveal_list, vote_hashes, last_block_number):

        t_pool2 = copy.deepcopy(self.transaction_pool)

        del self.transaction_pool[:]

        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..

        d = []

        for tx in tx_hash_list:
            for t in t_pool2:
                if tx == t.txhash:
                    d.append(t.txfrom)
                    self.transaction_pool.append(t)
                    t.nonce = self.state.state_nonce(t.txfrom) + d.count(t.txfrom)

        # create the block..

        block_obj = self.m_create_block(hashchain_hash, reveal_list, vote_hashes, last_block_number)

        # reset the pool back

        self.transaction_pool = copy.deepcopy(t_pool2)

        return block_obj

    # return a sorted list of txhashes from transaction_pool, sorted by timestamp from block n (actually from start of transaction_pool) to time, then ordered by txhash.

    def sorted_tx_pool(self, timestamp=None):
        if timestamp == None:
            timestamp = time()
        pool = copy.deepcopy(self.transaction_pool)
        trimmed_pool = []
        end_time = timestamp
        for tx in pool:
            if self.txhash_timestamp[self.txhash_timestamp.index(tx.txhash) + 1] <= end_time:
                trimmed_pool.append(tx.txhash)

        trimmed_pool.sort()

        if trimmed_pool == []:
            return False

        return trimmed_pool

    # merkle tree root hash of tx from pool for next POS block

    def merkle_tx_hash(self, hashes):
        # printL(( 'type', type(hashes), 'len', len(hashes)
        if len(hashes) == 64:  # if len = 64 then it is a single hash string rather than a list..
            return hashes
        j = int(ceil(log(len(hashes), 2)))
        l_array = []
        l_array.append(hashes)
        for x in range(j):
            next_layer = []
            i = len(l_array[x]) % 2 + len(l_array[x]) / 2
            z = 0
            for y in range(i):
                if len(l_array[x]) == z + 1:
                    next_layer.append(l_array[x][z])
                else:
                    next_layer.append(sha256(l_array[x][z] + l_array[x][z + 1]))
                z += 2
            l_array.append(next_layer)
        # printL(( l_array
        return ''.join(l_array[-1])

    # return closest hash in numerical terms to merkle root hash of all the supplied hashes..

    def closest_hash(self, list_hash):
        # printL(( 'list_hash', list_hash, len(list_hash)

        if type(list_hash) == list:
            if len(list_hash) == 1:
                return False, False
        if type(list_hash) == str:
            if len(list_hash) == 64:
                return False, False

        list_hash.sort()

        root = merkle_tx_hash(list_hash)

        p = []
        for l in list_hash:
            p.append(int(l, 16))

        closest = cl(int(root, 16), p)

        return ''.join(list_hash[p.index(closest)]), root

    # return closest number in a hexlified list

    def cl_hex(self, one, many):

        p = []
        for l in many:
            p.append(int(l, 16))

        return many[p.index(self.cl(int(one, 16), p))]

    # return closest number in a list..

    def cl(self, one, many):
        return min(many, key=lambda x: abs(x - one))

    def is_stake_banned(self, stake_address):
        if stake_address in self.stake_ban_list:
            epoch_diff = (self.height() / c.blocks_per_epoch) - (
                self.stake_ban_block[stake_address] / c.blocks_per_epoch)
            if self.height() - self.stake_ban_block[stake_address] > 10 or epoch_diff > 0:
                printL(('Stake removed from ban list'))
                del self.stake_ban_block[stake_address]
                self.stake_ban_list.remove(stake_address)
                return False
            return True

        return False

    def ban_stake(self, stake_address):
        printL(('stake address ', stake_address, ' added to block list'))
        self.stake_ban_list.append(stake_address)
        self.stake_ban_block[stake_address] = self.height() + 1

    # create a snapshot of the transaction pool to account for network traversal time (probably less than 300ms, but let's give a window of 1.5 seconds).
    # returns: list of merkle root hashes of the tx pool over last 1.5 seconds

    # import itertools
    # itertools.permutations([1, 2, 3])

    def pos_block_pool(self, n=1.5):
        timestamp = time()
        start_time = timestamp - n

        x = self.sorted_tx_pool(start_time)
        y = self.sorted_tx_pool(timestamp)
        if y == False:  # if pool is empty -> return sha256 null
            return [sha256('')], [[]]
        elif x == y:  # if the pool isnt empty but there is no difference then return the only merkle hash possible..
            return [self.merkle_tx_hash(y)], [y]
        else:  # there is a difference in contents of pool over last 1.5 seconds..
            merkle_hashes = []
            txhashes = []
            if x == False:
                merkle_hashes.append(sha256(''))
                x = []
                txhashes.append(x)
            else:
                merkle_hashes.append(self.merkle_tx_hash(x))
                txhashes.append(x)
            tmp_txhashes = x

            for tx in reversed(self.transaction_pool):
                if tx.txhash in y and tx.txhash not in x:
                    tmp_txhashes.append(tx.txhash)
                    tmp_txhashes.sort()
                    merkle_hashes.append(self.merkle_tx_hash(tmp_txhashes))
                    txhashes.append(tmp_txhashes)

            return merkle_hashes, txhashes

    # create the PRF selector sequence based upon a seed and number of stakers in list (temporary..there are better ways to do this with bigger seed value, but it works)

    def pos_block_selector(self, seed, n):
        n_bits = int(ceil(log(n, 2)))
        prf = merkle.GEN_range_bin(seed, 1, 20000, 1)
        prf_range = []
        for z in prf:
            x = ord(z) >> 8 - n_bits
            if x < n:
                prf_range.append(x)
        return prf_range

    # return the POS staker list position for given seed at index, i

    def pos_block_selector_n(self, seed, n, i):
        l = self.pos_block_selector(seed, n)
        return l[i]

    #### move from here
    # tx, address chain search functions

    def search_telnet(self, txcontains, long=1):
        tx_list = []
        hrs_list = []

        # because we allow hrs substitution in txto for transactions, we need to identify where this occurs for searching..

        if txcontains[0] == 'Q':
            for block in self.m_blockchain:
                for tx in block.transactions:
                    if tx.txfrom == txcontains:
                        if len(tx.hrs) > 0:
                            if self.state.state_hrs(tx.hrs) == txcontains:
                                hrs_list.append(tx.hrs)

        for tx in self.transaction_pool:
            if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains or tx.txto in hrs_list:
                # printL(( txcontains, 'found in transaction pool..'
                if long == 0: tx_list.append('<tx:txhash> ' + tx.txhash + ' <transaction_pool>')
                if long == 1: tx_list.append(helper.json_print_telnet(tx))

        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains or tx.txto in hrs_list:
                    # printL(( txcontains, 'found in block',str(block.blockheader.blocknumber),'..'
                    if long == 0: tx_list.append(
                        '<tx:txhash> ' + tx.txhash + ' <block> ' + str(block.blockheader.blocknumber))
                    if long == 1: tx_list.append(helper.json_print_telnet(tx))
        return tx_list

    # used for port 80 api - produces JSON output of a specific tx hash, including status of tx, in a block or unconfirmed + timestampe of parent block

    def search_txhash(self, txhash):  # txhash is unique due to nonce.
        for tx in self.transaction_pool:
            if tx.txhash == txhash:
                printL((txhash, 'found in transaction pool..'))
                tx_new = copy.deepcopy(tx)
                tx_new.block = 'unconfirmed'
                tx_new.hexsize = len(helper.json_bytestream(tx_new))
                tx_new.status = 'ok'
                return helper.json_print_telnet(tx_new)
        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txhash:
                    tx_new = copy.deepcopy(tx)
                    tx_new.block = block.blockheader.blocknumber
                    tx_new.timestamp = block.blockheader.timestamp
                    tx_new.confirmations = self.m_blockheight() - block.blockheader.blocknumber
                    tx_new.hexsize = len(helper.json_bytestream(tx_new))
                    tx_new.amount = tx_new.amount / 100000000.000000000
                    tx_new.fee = tx_new.fee / 100000000.000000000
                    printL((txhash, 'found in block', str(block.blockheader.blocknumber), '..'))
                    tx_new.status = 'ok'
                    return helper.json_print_telnet(tx_new)
        printL((txhash, 'does not exist in memory pool or local blockchain..'))
        err = {'status': 'Error', 'error': 'txhash not found', 'method': 'txhash', 'parameter': txhash}
        return helper.json_print_telnet(err)

    # return False

    # used for port 80 api - produces JSON output reporting every transaction for an address, plus final balance..

    def search_address(self, address):

        addr = {}
        addr['transactions'] = {}

        if self.state.state_address_used(address) != False:
            nonce, balance, pubhash_list = self.state.state_get_address(address)
            addr['state'] = {}
            addr['state']['address'] = address
            addr['state']['balance'] = balance / 100000000.000000000
            addr['state']['nonce'] = nonce

        for s in self.state.stake_list_get():
            if address == s[0]:
                addr['stake'] = {}
                addr['stake']['selector'] = s[2]
                # pubhashes used could be put here..

        for tx in self.transaction_pool:
            if tx.txto == address or tx.txfrom == address:
                printL((address, 'found in transaction pool'))
                addr['transactions'][tx.txhash] = {}
                addr['transactions'][tx.txhash]['txhash'] = tx.txhash
                addr['transactions'][tx.txhash]['block'] = 'unconfirmed'
                addr['transactions'][tx.txhash]['amount'] = tx.amount / 100000000.000000000
                addr['transactions'][tx.txhash]['fee'] = tx.fee / 100000000.000000000
                addr['transactions'][tx.txhash]['nonce'] = tx.nonce
                addr['transactions'][tx.txhash]['ots_key'] = tx.ots_key
                addr['transactions'][tx.txhash]['txto'] = tx.txto
                addr['transactions'][tx.txhash]['txfrom'] = tx.txfrom
                addr['transactions'][tx.txhash]['timestamp'] = 'unconfirmed'

        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txto == address or tx.txfrom == address:
                    printL((address, 'found in block ', str(block.blockheader.blocknumber), '..'))
                    addr['transactions'][tx.txhash] = {}
                    addr['transactions'][tx.txhash]['txhash'] = tx.txhash
                    addr['transactions'][tx.txhash]['block'] = block.blockheader.blocknumber
                    addr['transactions'][tx.txhash]['timestamp'] = block.blockheader.timestamp
                    addr['transactions'][tx.txhash]['amount'] = tx.amount / 100000000.000000000
                    addr['transactions'][tx.txhash]['fee'] = tx.fee / 100000000.000000000
                    addr['transactions'][tx.txhash]['nonce'] = tx.nonce
                    addr['transactions'][tx.txhash]['ots_key'] = tx.ots_key
                    addr['transactions'][tx.txhash]['txto'] = tx.txto
                    addr['transactions'][tx.txhash]['txfrom'] = tx.txfrom

        if len(addr['transactions']) > 0:
            addr['state']['transactions'] = len(addr['transactions'])

        if addr == {'transactions': {}}:
            addr = {'status': 'error', 'error': 'address not found', 'method': 'address', 'parameter': address}
        else:
            addr['status'] = 'ok'

        return helper.json_print_telnet(addr)

    # return json info on last n tx in the blockchain

    def last_tx(self, n=None):

        addr = {}
        addr['transactions'] = {}

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': n}

        if not n:
            n = 1

        try:
            n = int(n)
        except:
            return helper.json_print_telnet(error)

        if n <= 0 or n > 20:
            return helper.json_print_telnet(error)

        if len(self.transaction_pool) != 0:
            if n - len(self.transaction_pool) >= 0:  # request bigger than tx in pool
                z = len(self.transaction_pool)
                n = n - len(self.transaction_pool)
            elif n - len(self.transaction_pool) <= 0:  # request smaller than tx in pool..
                z = n
                n = 0

            for tx in reversed(self.transaction_pool[-z:]):
                addr['transactions'][tx.txhash] = {}
                addr['transactions'][tx.txhash]['txhash'] = tx.txhash
                addr['transactions'][tx.txhash]['block'] = 'unconfirmed'
                addr['transactions'][tx.txhash]['timestamp'] = 'unconfirmed'
                addr['transactions'][tx.txhash]['amount'] = tx.amount / 100000000.000000000
                addr['transactions'][tx.txhash]['type'] = tx.type

            if n == 0:
                addr['status'] = 'ok'
                return helper.json_print_telnet(addr)

        for block in reversed(self.m_blockchain):
            if len(block.transactions) > 0:
                for tx in reversed(block.transactions):
                    addr['transactions'][tx.txhash] = {}
                    addr['transactions'][tx.txhash]['txhash'] = tx.txhash
                    addr['transactions'][tx.txhash]['block'] = block.blockheader.blocknumber
                    addr['transactions'][tx.txhash]['timestamp'] = block.blockheader.timestamp
                    addr['transactions'][tx.txhash]['amount'] = tx.amount / 100000000.000000000
                    addr['transactions'][tx.txhash]['type'] = tx.type
                    n -= 1
                    if n == 0:
                        addr['status'] = 'ok'
                        return helper.json_print_telnet(addr)
        return helper.json_print_telnet(error)

    def richlist(self, n=None):  # only feasible while chain is small..
        if not n:
            n = 5

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'richlist', 'parameter': n}

        try:
            n = int(n)
        except:
            return helper.json_print_telnet(error)

        if n <= 0 or n > 20:
            return helper.json_print_telnet(error)

        if self.state.state_uptodate(self.m_blockheight()) == False:
            return helper.json_print_telnet({'status': 'error', 'error': 'leveldb failed', 'method': 'richlist'})

        addr = self.state.db.return_all_addresses()
        richlist = sorted(addr, key=itemgetter(1), reverse=True)

        rl = {}
        rl['richlist'] = {}

        if len(richlist) < n:
            n = len(richlist)

        for rich in richlist[:n]:
            rl['richlist'][richlist.index(rich) + 1] = {}
            rl['richlist'][richlist.index(rich) + 1]['address'] = rich[0]
            rl['richlist'][richlist.index(rich) + 1]['balance'] = rich[1] / 100000000.000000000

        rl['status'] = 'ok'

        return helper.json_print_telnet(rl)

    # return json info on last n blocks

    def last_block(self, n=None):

        if not n:
            n = 1

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_block', 'parameter': n}

        try:
            n = int(n)
        except:
            return helper.json_print_telnet(error)

        if n <= 0 or n > 20:
            return helper.json_print_telnet(error)

        lb = self.m_blockchain[-n:]

        last_blocks = {}
        last_blocks['blocks'] = {}

        for block in reversed(lb):
            last_blocks['blocks'][block.blockheader.blocknumber] = {}
            last_blocks['blocks'][block.blockheader.blocknumber][
                'block_reward'] = block.blockheader.block_reward / 100000000.00000000
            last_blocks['blocks'][block.blockheader.blocknumber]['blocknumber'] = block.blockheader.blocknumber
            last_blocks['blocks'][block.blockheader.blocknumber]['blockhash'] = block.blockheader.prev_blockheaderhash
            last_blocks['blocks'][block.blockheader.blocknumber][
                'number_transactions'] = block.blockheader.number_transactions
            last_blocks['blocks'][block.blockheader.blocknumber]['number_stake'] = block.blockheader.number_stake
            last_blocks['blocks'][block.blockheader.blocknumber]['timestamp'] = block.blockheader.timestamp
            last_blocks['blocks'][block.blockheader.blocknumber]['block_interval'] = block.blockheader.timestamp - \
                                                                                     self.m_blockchain[
                                                                                         block.blockheader.blocknumber - 1].blockheader.timestamp

        last_blocks['status'] = 'ok'

        return helper.json_print_telnet(last_blocks)

    # return json info on stake_commit list

    def stake_commits(self, data=None):

        sc = {}
        sc['status'] = 'ok'
        sc['commits'] = {}

        for c in self.stake_commit:
            # [stake_address, block_number, merkle_hash_tx, commit_hash]
            sc['commits'][str(c[1]) + '-' + c[3]] = {}
            sc['commits'][str(c[1]) + '-' + c[3]]['stake_address'] = c[0]
            sc['commits'][str(c[1]) + '-' + c[3]]['block_number'] = c[1]
            sc['commits'][str(c[1]) + '-' + c[3]]['merkle_hash_tx'] = c[2]
            sc['commits'][str(c[1]) + '-' + c[3]]['commit_hash'] = c[3]

        return helper.json_print_telnet(sc)

    def stakers(self, data=None):
        # (stake -> address, hash_term, nonce)
        stakers = {}
        stakers['status'] = 'ok'
        stakers['stake_list'] = {}
        for s in self.state.stake_list_get():
            stakers['stake_list'][s[0]] = {}
            stakers['stake_list'][s[0]]['address'] = s[0]
            stakers['stake_list'][s[0]]['balance'] = self.state.state_balance(s[0]) / 100000000.00000000
            stakers['stake_list'][s[0]]['hash_terminator'] = s[1]
            stakers['stake_list'][s[0]]['nonce'] = s[2]

        return helper.json_print_telnet(stakers)

    def next_stakers(self, data=None):
        # (stake -> address, hash_term, nonce)
        next_stakers = {}
        next_stakers['status'] = 'ok'
        next_stakers['stake_list'] = {}
        for s in self.state.next_stake_list_get():
            next_stakers['stake_list'][s[0]] = {}
            next_stakers['stake_list'][s[0]]['address'] = s[0]
            next_stakers['stake_list'][s[0]]['balance'] = self.state.state_balance(s[0]) / 100000000.00000000
            next_stakers['stake_list'][s[0]]['hash_terminator'] = s[1]
            next_stakers['stake_list'][s[0]]['nonce'] = s[2]

        return helper.json_print_telnet(next_stakers)

    def exp_win(self, data=None):
        # chain.expected_winner.append([chain.m_blockchain[-1].blockheader.blocknumber+1, winner, winning_staker])
        ew = {}
        ew['status'] = 'ok'
        ew['expected_winner'] = {}
        for e in expected_winner:
            ew['expected_winner'][e[0]] = {}
            ew['expected_winner'][e[0]]['hash'] = e[1]
            ew['expected_winner'][e[0]]['stake_address'] = e[2]
        return helper.json_print_telnet(ew)

    def stake_reveal_ones(self, data=None):

        sr = {}
        sr['status'] = 'ok'
        sr['reveals'] = {}
        # chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one]) #merkle_hash_tx, commit_hash])
        for c in self.stake_reveal_one:
            sr['reveals'][str(c[1]) + '-' + str(c[2])] = {}
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['stake_address'] = c[0]
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['block_number'] = c[2]
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['headerhash'] = c[1]
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['reveal'] = c[3]

        return helper.json_print_telnet(sr)

    def ip_geotag(self, data=None):

        ip = {}
        ip['status'] = 'ok'
        ip['ip_geotag'] = {}
        ip['ip_geotag'] = self.ip_list

        x = 0
        for i in self.ip_list:
            ip['ip_geotag'][x] = i
            x += 1

        return helper.json_print_telnet(ip)

    def stake_reveals(self, data=None):

        sr = {}
        sr['status'] = 'ok'
        sr['reveals'] = {}
        # chain.stake_reveal.append([stake_address, block_number, merkle_hash_tx, reveal])
        for c in self.stake_reveal:
            sr['reveals'][str(c[1]) + '-' + c[3]] = {}
            sr['reveals'][str(c[1]) + '-' + c[3]]['stake_address'] = c[0]
            sr['reveals'][str(c[1]) + '-' + c[3]]['block_number'] = c[1]
            sr['reveals'][str(c[1]) + '-' + c[3]]['merkle_hash_tx'] = c[2]
            sr['reveals'][str(c[1]) + '-' + c[3]]['reveal'] = c[3]

        return helper.json_print_telnet(sr)

    def search(self, txcontains, long=1):
        for tx in self.transaction_pool:
            if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
                printL((txcontains, 'found in transaction pool..'))
                if long == 1: helper.json_print(tx)
        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
                    printL((txcontains, 'found in block', str(block.blockheader.blocknumber), '..'))
                    if long == 0: printL(('<tx:txhash> ' + tx.txhash))
                    if long == 1: helper.json_print(tx)
        return

    def f_read_chain(self, epoch):
        delimiter = c.binary_file_delimiter
        block_list = []
        if os.path.isfile('./chain.da' + str(epoch)) is False:
            if epoch != 0:
                return []
            printL(('Creating new chain file'))
            block_list.append(CreateGenesisBlock(self))
            return block_list

        try:
            with open('./chain.da'+str(epoch), 'r') as myfile:
                jsonBlock = StringIO()
                tmp = ""
                count = 0
                offset = 0
                while True:
                    chars = myfile.read(c.chain_read_buffer_size)
                    for char in chars:
                        offset += 1
                        if count>0 and char!=delimiter[count]:
                            count = 0
                            jsonBlock.write(tmp)
                            tmp = ""
                        if char == delimiter[count]:
                            tmp += delimiter[count]
                            count += 1
                            if count < len(delimiter):
                                continue
                            tmp = ""
                            count = 0
                            compressedBlock = jsonBlock.getvalue()
                            pos = offset - len(delimiter) - len(compressedBlock)
                            jsonBlock = zip.decompress(compressedBlock)
                            block = helper.json_decode_block(jsonBlock)
                            self.update_block_metadata(block.blockheader.blocknumber, pos, len(compressedBlock))
                            block_list.append(block)
                            jsonBlock = StringIO()
                            continue
                        jsonBlock.write(char)
                    if len(chars) < c.chain_read_buffer_size:
                        break
        except:
            printL(('IO error'))
            return []

        gc.collect()
        return block_list


    '''
    def f_read_chain(self, epoch):
        block_list = []

        if os.path.isfile('./chain.da'+str(epoch)) is False:
            if epoch != 0:
                return None
            printL(('Creating new chain file'))
            block_list.append(CreateGenesisBlock(self))
            with open("./chain.da"+str(epoch), "a") as myfile:  # add in a new call to create random_otsmss
                pickle.dump(block_list, myfile)
                gc.collect()
        try:
            with open('./chain.da'+str(epoch), 'r') as myfile:
                return pickle.load(myfile)
        except:
            printL(('IO error'))
            return None
    '''
    '''
    def f_read_chain(self):
        block_list = []
        if os.path.isfile('./chain.dat') is False:
            printL(('Creating new chain file'))
            block_list.append(CreateGenesisBlock(self))
            with open("./chain.dat", "a") as myfile:  # add in a new call to create random_otsmss
                pickle.dump(block_list, myfile)
                gc.collect()
        try:
            with open('./chain.dat', 'r') as myfile:
                return pickle.load(myfile)
        except:
            printL(('IO error'))
            return False
    '''
    def f_get_last_block(self):
        return self.f_read_chain()[-1]

    def f_write_chain(self, block_data):
        data = self.f_read_chain()
        for block in block_data:
            data.append(block)
        if block_data is not False:
            printL(('Appending data to chain'))
            with open("./chain.dat",
                      "w+") as myfile:  # overwrites self.wallet..must use w+ as cannot append pickle item
                pickle.dump(data, myfile)

        gc.collect()
        return

    def update_block_metadata(self, blocknumber, blockPos, blockSize):
        self.state.db.db.Put('block_' + str(blocknumber), str(blockPos) + ',' + str(blockSize))

    def f_write_m_blockchain(self):
        blocknumber = self.m_blockchain[-1].blockheader.blocknumber
        suffix = int(blocknumber // c.blocks_per_chain_file)
        writeable = self.m_blockchain[-c.disk_writes_after_x_blocks:]
        printL(('Appending data to chain'))
        with open('./chain.da'+str(suffix), 'a') as myfile:
            for block in writeable:
                jsonBlock = helper.json_bytestream(block)
                compressedBlock = zip.compress(jsonBlock, c.compression_level)
                pos = myfile.tell()
                blockSize = len(compressedBlock)
                self.update_block_metadata(block.blockheader.blocknumber, pos, blockSize)
                myfile.write(compressedBlock)
                myfile.write(c.binary_file_delimiter)
        del self.m_blockchain[:-1]
        gc.collect()
        return

    def load_chain_by_epoch(self, epoch):

        chains = self.f_read_chain(epoch)
        self.m_blockchain.append(chains[0])
        self.state.state_read_genesis(self.m_get_block(0))
        self.block_chain_buffer = ChainBuffer(self)

        for block in chains[1:]:
            self.block_chain_buffer.add_block_mainchain(block, verify_block_reveal_list=False, validate=False)
        return self.m_blockchain

    def m_load_chain(self):

        del self.m_blockchain[:]
        self.state.db.zero_all_addresses()
        chains = self.f_read_chain(0)
        self.m_blockchain.append(chains[0])
        self.state.state_read_genesis(self.m_get_block(0))
        self.block_chain_buffer = ChainBuffer(self)

        for block in chains[1:]:
            self.block_chain_buffer.add_block_mainchain(block, verify_block_reveal_list=False, validate=False)

        if len(self.m_blockchain) < c.blocks_per_chain_file:
            return self.m_blockchain

        epoch = 1
        while os.path.isfile('./chain.da' + str(epoch)):
            del self.m_blockchain[:-1]
            chains = self.f_read_chain(epoch)

            for block in chains:
                self.block_chain_buffer.add_block_mainchain(block, verify_block_reveal_list=False, validate=False)
            epoch += 1

        gc.collect()
        return self.m_blockchain

    def m_read_chain(self):
        if not self.m_blockchain:
            self.m_load_chain()
        return self.m_blockchain

    def load_from_file(self, blocknum):
        epoch = int( blocknum // c.blocks_per_chain_file )
        with open('chain.da'+str(epoch), 'r') as f:
            pos_size = self.state.db.db.Get('block_'+str(blocknum))
            pos, size = pos_size.split(',')
            pos = int(pos)
            size = int(size)
            f.seek(pos)
            jsonBlock = zip.decompress(f.read(size))
            block = helper.json_decode_block(jsonBlock)
            return block

    def m_get_block(self, n):
        if len(self.m_blockchain) == 0:
            return False

        beginning_blocknum = self.m_blockchain[0].blockheader.blocknumber
        diff = n - beginning_blocknum

        if diff < 0:
            return self.load_from_file(n)

        if diff < len(self.m_blockchain):
            return self.m_blockchain[diff]



        return False

    def m_get_last_block(self):
        if len(self.m_blockchain) == 0:
            return False
        return self.m_blockchain[-1]

    def m_create_block(self, nonce, reveal_list=[], vote_hashes=[], last_block_number=-1):
        myBlock = Block()
        myBlock.create(self, nonce, reveal_list, vote_hashes, last_block_number)
        return myBlock

    def m_add_block(self, block_obj, verify_block_reveal_list=True):
        if len(self.m_blockchain) == 0:
            self.m_read_chain()

        if block_obj.validate_block(chain=self, verify_block_reveal_list=verify_block_reveal_list) is True:
            if self.state.state_add_block(self, block_obj) is True:
                self.m_blockchain.append(block_obj)
                self.remove_tx_in_block_from_pool(block_obj)
                self.remove_st_in_block_from_pool(block_obj)
            else:
                printL(('last block failed state/stake checks, removed from chain'))
                self.state.state_validate_tx_pool(self)
                return False
        else:
            printL(('m_add_block failed - block failed validation.'))
            return False
        self.m_f_sync_chain()
        return True

    def m_remove_last_block(self):
        if not self.m_blockchain:
            self.m_read_chain()
        self.m_blockchain.pop()

    def m_blockheight(self):
        #return len(self.m_read_chain()) - 1
        return self.height()


    def height(self):
        if len(self.m_blockchain):
            return self.m_blockchain[-1].blockheader.blocknumber
        return -1

    def m_info_block(self, n):
        if n > self.m_blockheight():
            printL(('No such block exists yet..'))
            return False
        b = self.m_get_block(n)
        printL(('Block: ', b, str(b.blockheader.blocknumber)))
        printL(('Blocksize, ', str(len(helper.json_bytestream(b)))))
        printL(('Number of transactions: ', str(len(b.transactions))))
        printL(('Validates: ', b.validate_block(self)))

    def m_f_sync_chain(self):
        if (self.m_blockchain[-1].blockheader.blocknumber + 1) % c.disk_writes_after_x_blocks == 0:
            self.f_write_m_blockchain()
        return

    def m_verify_chain(self, verbose=0):
        for block in self.m_read_chain()[1:]:
            if block.validate_block(self, verbose=verbose) is False:
                return False
        return True

    def m_verify_chain_250(self, verbose=0):  # validate the last 250 blocks or len(m_blockchain)-1..
        n = 0
        if len(self.m_blockchain) > 250:
            x = 250
        else:
            if len(self.m_blockchain) == 1:
                return True
            x = len(self.m_blockchain) - 1

        for block in self.m_read_chain()[-x:]:
            if self.validate_block(block, verbose=verbose) is False:
                printL(('block failed:', block.blockheader.blocknumber))
                return False
            n += 1
            if verbose is 1:
                sys.stdout.write('.')
                sys.stdout.flush()
        return True

    # validate and update stake+state for newly appended block.
    # can be streamlined to reduce repetition in the added components..
    # finish next epoch code..


    def add_tx_to_pool(self, tx_class_obj):
        self.transaction_pool.append(tx_class_obj)
        self.txhash_timestamp.append(tx_class_obj.txhash)
        self.txhash_timestamp.append(time())

    def add_st_to_pool(self, st_class_obj):
        self.stake_pool.append(st_class_obj)

    def remove_tx_from_pool(self, tx_class_obj):
        self.transaction_pool.remove(tx_class_obj)
        self.txhash_timestamp.pop(self.txhash_timestamp.index(tx_class_obj.txhash) + 1)
        self.txhash_timestamp.remove(tx_class_obj.txhash)

    def remove_st_from_pool(self, st_class_obj):
        self.stake_pool.remove(st_class_obj)

    def show_tx_pool(self):
        return self.transaction_pool

    def remove_tx_in_block_from_pool(self, block_obj):
        for tx in block_obj.transactions:
            for txn in self.transaction_pool:
                if tx.txhash == txn.txhash:
                    self.remove_tx_from_pool(txn)

    def remove_st_in_block_from_pool(self, block_obj):
        for st in block_obj.stake:
            for stn in self.stake_pool:
                if st.hash == stn.hash:
                    self.remove_st_from_pool(stn)

    def flush_tx_pool(self):
        del self.transaction_pool[:]

    def flush_st_pool(self):
        del self.stake_pool[:]

    def validate_tx_pool(self):  # invalid transactions are auto removed from pool..
        for transaction in self.transaction_pool:
            if transaction.validate_tx() is False:
                self.remove_tx_from_pool(transaction)
                printL(('invalid tx: ', transaction, 'removed from pool'))

        return True

    def create_my_tx(self, txfrom, txto, amount, fee=0):
        if isinstance(txto, int):
            txto = self.my[txto][0]

        tx = SimpleTransaction().create_simple_transaction(state=self.state, txfrom=self.my[txfrom][0], txto=txto,
                                                           amount=amount, data=self.my[txfrom][1], fee=fee)

        if tx and tx.state_validate_tx(state=self.state, transaction_pool=self.transaction_pool):
            self.add_tx_to_pool(tx)
            self.wallet.f_save_winfo()  # need to keep state after tx ..use self.wallet.info to store index..far faster than loading the 55mb self.wallet..
            return tx

        return False


class BlockBuffer:
    def __init__(self, block, stake_reward, chain, seed, balance):#, prev_seed):
        self.block = block
        self.stake_reward = stake_reward
        self.score = self.block_score(chain, seed, balance)
        #self.seed = sha256(block.blockheader.headerhash + str(prev_seed))

    def block_score(self, chain, seed, balance):
        stake_selector = self.block.blockheader.stake_selector

        seed = int(str(seed), 16)
        score_val = chain.score(stake_address=self.block.blockheader.stake_selector,
                                reveal_one=self.block.blockheader.hash,
                                balance=balance,
                                seed=seed,
                                verbose=False)
        return score_val


class StateBuffer:
    def __init__(self):
        self.stake_list = {}
        self.next_stake_list = {}
        self.next_seed = None ##
        self.hash_chain = None ##

    def set_next_seed(self, winning_reveal, prev_seed):
        self.next_seed = sha256(winning_reveal + str(prev_seed))

    def tx_to_list(self, txn_dict):
        tmp_sl = []
        for txfrom in txn_dict:
            st = txn_dict[txfrom]
            if not st[3]:  # rejecting ST having first_hash None
                continue
            tmp_sl.append(st)
        return tmp_sl

    def update(self, state, parent_state_buffer, block):
        #epoch mod, helps you to know if its the new epoch
        epoch_mod = block.blockheader.blocknumber % c.blocks_per_epoch

        self.stake_list = deepcopy(parent_state_buffer.stake_list)
        self.next_stake_list = deepcopy(parent_state_buffer.next_stake_list)
        #TODO filter all next_stake_list with first_reveal None
        #Before adding_block, check if the stake_selector is in stake_list
        self.set_next_seed(block.blockheader.hash, parent_state_buffer.next_seed)
        self.hash_chain = deepcopy(parent_state_buffer.hash_chain)

        if not epoch_mod:   #State belongs to first block of next epoch
            self.stake_list = self.next_stake_list
            self.next_stake_list = {}

            tmp_sl = self.tx_to_list(self.stake_list)

            self.stake_list = {}
            for st in tmp_sl:
                self.stake_list[st[0]] = st

        if epoch_mod == c.blocks_per_epoch - 1:
            tmp_sl = self.tx_to_list(self.next_stake_list)

            self.next_seed = state.calc_seed(tmp_sl, verbose=False)

        self.update_stake_list(block)
        self.update_next_stake_list(block, state)

    def update_next_stake_list(self, block, state):
        for st in block.stake:
            if st.txfrom in self.next_stake_list and self.next_stake_list[st.txfrom][3]:
                continue
            self.next_stake_list[st.txfrom] = [st.txfrom, st.hash, 0, st.first_hash, st.balance]

    def update_stake_list(self, block):
        stake_selector = block.blockheader.stake_selector
        if stake_selector not in self.stake_list:
            printL (( 'Error Stake selector not found stake_list of block buffer state' ))
            raise Exception
        self.stake_list[stake_selector][2] += 1


class ChainBuffer:
    def __init__(self, chain):
        self.chain = chain
        self.state = self.chain.state
        self.wallet = self.chain.wallet
        self.blocks = {}
        self.strongest_chain = {}
        self.headerhashes = {}
        self.size = c.reorg_limit
        self.pending_blocks = {}
        self.epoch = max(0, self.chain.height()) // c.blocks_per_epoch  # Main chain epoch
        self.my = {}
        self.my[self.epoch] = deepcopy(self.chain.my)
        self.epoch_seed = None
        self.hash_chain = {}
        self.hash_chain[self.epoch] = self.chain.my[0][1].hc
        #self.tx_buffer = []  # maintain the list of tx transaction that has been confirmed in buffer
        #self.st_buffer = []  # maintain the list of st transaction that has been confirmed in buffer
        self.tx_buffer = {}  # maintain the list of tx transaction that has been confirmed in buffer
        self.st_buffer = {}  # maintain the list of st transaction that has been confirmed in buffer
        if self.chain.height() > 0:
            self.epoch = int(self.chain.m_blockchain[-1].blockheader.blocknumber / c.blocks_per_epoch)

    def get_st_balance(self, stake_address, blocknumber):
        if stake_address is None:
            printL (('stake address should not be none'))
            raise Exception
            return None
        if blocknumber-1 == self.chain.height():
            for st in self.state.stake_list_get():
                if stake_address == st[0]:
                    #printL (( 'balance by 1 '))
                    return st[-1]
            printL (('Blocknumber not found'))
            return None

        if blocknumber-1 not in self.strongest_chain:
            printL (('Blocknumber not in strongest chain'))
            return None

        if blocknumber % c.blocks_per_epoch == 0:
            #printL(('balance by 2 '))
            return self.strongest_chain[blocknumber-1][1].next_stake_list[stake_address][-1]
        #printL(('balance by 3 '))
        return self.strongest_chain[blocknumber - 1][1].stake_list[stake_address][-1]

    def add_pending_block(self, block):
        # TODO : minimum block validation in unsynced state

        blocknum = block.blockheader.blocknumber
        headerhash = block.blockheader.headerhash

        if blocknum not in self.pending_blocks:
            self.pending_blocks[blocknum] = []

        if headerhash in self.pending_blocks[blocknum]:
            return

        self.pending_blocks[blocknum].append(block)

        return True

    def get_last_block(self):
        if len(self.strongest_chain) == 0:
            return self.chain.m_get_last_block()
        last_blocknum = max(self.strongest_chain)
        return self.strongest_chain[last_blocknum][0].block

    def get_block_n(self, blocknum):
        if self.chain.height() == -1:
            self.chain.m_read_chain()

        if blocknum <= self.chain.height():
            return self.chain.m_get_block(blocknum)

        if blocknum not in self.strongest_chain:
            return None
        return self.strongest_chain[blocknum][0].block

    def hash_chain_get(self, blocknumber):
        epoch = int(blocknumber // c.blocks_per_epoch)
        return self.hash_chain[epoch]

    def update_hash_chain(self, blocknumber):
        epoch = int((blocknumber + 1) // c.blocks_per_epoch)
        printL(('Created new hash chain'))
        #self.chain.my[0][1].hashchain(epoch=epoch)
        new_my = deepcopy(self.my[epoch-1])
        new_my[0][1].hashchain(epoch=epoch)
        self.my[epoch] = new_my
        self.hash_chain[epoch] = new_my[0][1].hc
        #self.wallet.f_save_wallet()
        gc.collect()

    def add_txns_buffer(self):
        if len(self.blocks) == 0:
            return
        del self.tx_buffer
        del self.st_buffer
        self.tx_buffer = {}
        self.st_buffer = {}
        min_blocknum = self.chain.height() + 1
        #max_blocknum = max(self.blocks.keys())
        max_blocknum = max(self.strongest_chain.keys())

        #prev_headerhash = self.chain.m_blockchain[min_blocknum - 1].blockheader.headerhash
        for blocknum in range(min_blocknum, max_blocknum + 1):
            #block_state_buffer = self.get_strongest_block(blocknum, prev_headerhash)
            block_state_buffer = self.strongest_chain[blocknum]
            block = block_state_buffer[0].block
            #prev_headerhash = block.blockheader.headerhash
            self.st_buffer[blocknum] = []
            self.tx_buffer[blocknum] = []
            for st in block.stake:
                self.st_buffer[blocknum].append(st.get_message_hash())  # Assuming stake transactions are valid

            for tx in block.transactions:
                self.tx_buffer[blocknum].append(tx.txhash)

    def add_block_mainchain(self, block, verify_block_reveal_list=True, validate=True):
        # TODO : minimum block validation in unsynced state
        blocknum = block.blockheader.blocknumber
        epoch = int(blocknum // c.blocks_per_epoch)
        prev_epoch = int((blocknum - 1 ) // c.blocks_per_epoch)
        headerhash = block.blockheader.headerhash
        prev_headerhash = block.blockheader.prev_blockheaderhash

        if blocknum <= self.chain.height():
            return

        if blocknum - 1 == self.chain.height():
            if prev_headerhash != self.chain.m_blockchain[-1].blockheader.headerhash:
                printL(('prev_headerhash of block doesnt match with headerhash of m_blockchain'))
                return
        elif blocknum - 1 > 0:
            if blocknum - 1 not in self.blocks or prev_headerhash not in self.headerhashes[blocknum - 1]:
                printL(('No block found in buffer that matches with the prev_headerhash of received block'))
                return

        if validate:
            if not self.chain.m_add_block(block, verify_block_reveal_list):
                printL(("Failed to add block by m_add_block, re-requesting the block #", blocknum))
                return
        else:
            if self.state.state_add_block(self.chain, block) is True:
                self.chain.m_blockchain.append(block)

        block_left = c.blocks_per_epoch - (
            block.blockheader.blocknumber - (block.blockheader.epoch * c.blocks_per_epoch))

        self.add_txns_buffer()
        if block_left == 1:  # As state_add_block would have already moved the next stake list to stake_list
            self.epoch_seed = self.state.calc_seed(self.state.stake_list_get(), verbose=False)
            #self.update_hash_chain(block.blockheader.blocknumber)
            self.my[epoch + 1] = self.chain.my
            self.hash_chain[epoch + 1] = self.chain.my[0][1].hc
            if epoch in self.my:
                del self.my[epoch]
        else:
            self.epoch_seed = sha256(block.blockheader.hash + str(self.epoch_seed))

        self.epoch = epoch
        return True

    def add_block(self, block):
        # TODO : minimum block validation in unsynced state
        blocknum = block.blockheader.blocknumber
        headerhash = block.blockheader.headerhash
        prev_headerhash = block.blockheader.prev_blockheaderhash

        if blocknum <= self.chain.height():
            return True

        if blocknum - 1 == self.chain.height():
            if prev_headerhash != self.chain.m_blockchain[-1].blockheader.headerhash:
                printL(('Failed due to prevheaderhash mismatch, blockslen ', len(self.blocks)))
                return
        else:
            if blocknum - 1 not in self.blocks or prev_headerhash not in self.headerhashes[blocknum - 1]:
                printL(('Failed due to prevheaderhash mismatch, blockslen ', len(self.blocks)))
                return

        if blocknum not in self.blocks:
            self.blocks[blocknum] = []
            self.headerhashes[blocknum] = []

        if headerhash in self.headerhashes[blocknum]:
            return 0

        if min(self.blocks) + self.size <= blocknum:
            self.move_to_mainchain()

        stake_reward = {}

        state_buffer = StateBuffer()
        block_buffer = None
        if blocknum-1 == self.chain.height():
            tmp_stake_list = self.state.stake_list_get()
            for st in tmp_stake_list:
                state_buffer.stake_list[st[0]] = st

            tmp_next_stake_list = self.state.next_stake_list_get()
            for st in tmp_next_stake_list:
                state_buffer.next_stake_list[st[0]] = st
            block_buffer = BlockBuffer(block, stake_reward, self.chain, self.epoch_seed, self.get_st_balance(block.blockheader.stake_selector, block.blockheader.blocknumber))
            state_buffer.set_next_seed(block.blockheader.hash, self.epoch_seed)
            state_buffer.update_stake_list(block)
            state_buffer.update_next_stake_list(block, self.state)
        else:
            parent_state_buffer = None
            parent_seed = None
            for buffer in self.blocks[blocknum-1]:
                prev_block = buffer[0].block
                if prev_block.blockheader.headerhash == prev_headerhash:
                    parent_state_buffer = buffer[1]
                    parent_seed = buffer[1].next_seed
                    break
            block_buffer = BlockBuffer(block, stake_reward, self.chain, parent_seed, self.get_st_balance(block.blockheader.stake_selector, block.blockheader.blocknumber))
            state_buffer.update(self.state, parent_state_buffer, block)
        self.blocks[blocknum].append([block_buffer, state_buffer])

        if len(self.strongest_chain) == 0 and self.chain.m_blockchain[-1].blockheader.headerhash==prev_headerhash:
            self.strongest_chain[blocknum] = [block_buffer, state_buffer]
        elif blocknum not in self.strongest_chain and self.strongest_chain[blocknum - 1][0].block.blockheader.headerhash == prev_headerhash:
            self.strongest_chain[blocknum] = [block_buffer, state_buffer]
        elif blocknum in self.strongest_chain:
            old_block_buffer = self.strongest_chain[blocknum][0]
            if old_block_buffer.block.blockheader.prev_blockheaderhash == block_buffer.block.blockheader.prev_blockheaderhash:
                if block_buffer.score < old_block_buffer.score:
                    self.strongest_chain[blocknum] = [block_buffer, state_buffer]
                    if blocknum + 1 in self.strongest_chain:
                        self.recalculate_strongest_chain(blocknum)

        self.headerhashes[blocknum].append(block.blockheader.headerhash)

        #block_left = c.blocks_per_epoch - (
        #    block.blockheader.blocknumber - (block.blockheader.epoch * c.blocks_per_epoch))
        epoch = blocknum // c.blocks_per_epoch
        next_epoch = (blocknum + 1) // c.blocks_per_epoch
        if epoch != next_epoch:
            self.update_hash_chain(block.blockheader.blocknumber)

        self.add_txns_buffer()

        return True

    def recalculate_strongest_chain(self, blocknum):
        if blocknum+1 not in self.strongest_chain:
            return

        for i in range(blocknum+1, max(self.strongest_chain)+1):
            del self.strongest_chain[i]

        block = self.strongest_chain[blocknum].block
        prev_headerhash = block.blockheader.headerhash
        blocknum += 1
        block_state_buffer = self.get_strongest_block(blocknum, prev_headerhash)

        while block_state_buffer is not None:
            self.strongest_chain[blocknum] = block_state_buffer

            block_buffer = block_state_buffer[0]
            state_buffer = block_state_buffer[1]
            block = block_buffer.block

            prev_headerhash = block.blockheader.headerhash
            blocknum += 1
            block_state_buffer = self.get_strongest_block(blocknum, prev_headerhash)

    def get_strongest_block(self, blocknum, prev_headerhash):
        if blocknum not in self.blocks:
            return None
        strongest_blockBuffer = None

        for blockStateBuffer in self.blocks[blocknum]:
            block = blockStateBuffer[0].block
            if prev_headerhash == block.blockheader.prev_blockheaderhash:
                if strongest_blockBuffer and strongest_blockBuffer[0].score < blockStateBuffer[0].score:
                    continue
                strongest_blockBuffer = blockStateBuffer

        if not strongest_blockBuffer:
            return None

        return strongest_blockBuffer

    def get_strongest_headerhash(self, blocknum):
        if blocknum <= self.chain.height():
            return self.chain.m_get_block(blocknum).blockheader.headerhash
            #return self.chain.m_blockchain[blocknum].blockheader.headerhash

        if blocknum not in self.strongest_chain:
            printL(('Blocknum : ', str(blocknum), ' not found in buffer'))
            return None

        return self.strongest_chain[blocknum][0].block.blockheader.headerhash

    def get_epoch_seed(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return int(str(self.epoch_seed), 16)
        if blocknumber - 1 not in self.strongest_chain:
            return None
        return int(str(self.strongest_chain[blocknumber - 1][1].next_seed), 16)

    def stake_list_get(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return self.state.stake_list_get()

        if blocknumber - 1 not in self.strongest_chain:
            return None

        stateBuffer = self.strongest_chain[blocknumber - 1][1]
        if blocknumber % c.blocks_per_epoch == 0:
            return stateBuffer.tx_to_list(stateBuffer.next_stake_list)

        return stateBuffer.tx_to_list(stateBuffer.stake_list)

    def next_stake_list_get(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return self.state.next_stake_list_get()

        next_stake_list = self.strongest_chain[blocknumber - 1][1].next_stake_list
        tmp_stake_list = []
        for txfrom in next_stake_list:
            tmp_stake_list.append(next_stake_list[txfrom])

        return tmp_stake_list

    def describe(self):
        if len(self.blocks) == 0:
            return
        min_block = min(self.blocks)
        max_block = max(self.blocks)
        printL(('=' * 40))
        for blocknum in range(min_block, max_block + 1):
            printL(('Block number #', str(blocknum)))
            for buffer in self.blocks[blocknum]:
                blockBuffer = buffer[0]
                block = blockBuffer.block
                printL((block.blockheader.headerhash, ' ', str(blockBuffer.score), ' ',
                        str(block.blockheader.block_reward)))
                printL((block.blockheader.hash, ' ', block.blockheader.stake_selector))
        printL(('=' * 40))

    def move_to_mainchain(self):
        blocknum = self.chain.height() + 1
        block = self.strongest_chain[blocknum][0].block
        if not self.state.state_add_block(self.chain, block):
            printL(('last block failed state/stake checks, removed from chain'))
            return False

        self.chain.m_blockchain.append(block)
        self.chain.remove_tx_in_block_from_pool(block)  # modify fn to keep transaction in memory till reorg
        self.chain.remove_st_in_block_from_pool(block)  # modify fn to keep transaction in memory till reorg
        self.chain.m_f_sync_chain()

        self.epoch_seed = self.strongest_chain[blocknum][1].next_seed

        del (self.blocks[blocknum])
        del (self.headerhashes[blocknum])
        del self.strongest_chain[blocknum]
        prev_epoch = int((blocknum - 1) // c.blocks_per_epoch )
        self.epoch = int(blocknum // c.blocks_per_epoch)
        if prev_epoch != self.epoch:
            if prev_epoch in self.my:
                del self.my[prev_epoch]
            if prev_epoch in self.hash_chain:
                del self.hash_chain[prev_epoch]

        gc.collect()
        return True

    def height(self):
        if len(self.strongest_chain) == 0:
            return self.chain.height()
        return max(self.strongest_chain)

    def send_block(self, blocknumber, transport, wrap_message):
        if blocknumber <= self.chain.height():
            transport.write(wrap_message('PB', helper.json_bytestream(self.chain.m_get_block(blocknumber))))
        elif blocknumber in self.blocks:
            tmp = {blocknumber: []}
            for blockStateBuffer in self.blocks[blocknumber]:
                tmp[blocknumber].append(blockStateBuffer[0].block)
            transport.write(wrap_message('PBB', helper.json_encode_complex(tmp)))

    def process_pending_blocks(self):
        min_blocknum = min(self.pending_blocks.keys())
        max_blocknum = max(self.pending_blocks.keys())
        printL(('Processing pending blocks', min_blocknum, max_blocknum))
        for blocknum in range(min_blocknum, max_blocknum + 1):
            for block in self.pending_blocks[blocknum]:
                self.add_block(block)
            del self.pending_blocks[blocknum]
