# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# QRL main blockchain, state, stake, transaction functions.

# todo:
# pos_block_pool() should return all combinations, not just the order received then sorted by txhash - removes edge cases for block selection failure..
# add stake list check to the state check - addresses which are staking cannot make transactions..
# block-reward calculation to be altered based upon block-time and stake_list_get() balances..proportion of entire coin supply..
# fees
# occasionally the ots index gets behind..find reason..
# add salt/key xor to hash chains..
from qrlcore import logger
import configuration as config

__author__ = 'pete'

import gc

import bz2
from StringIO import StringIO
from time import time
from operator import itemgetter
from math import log, ceil
import heapq

import os, copy, sys
from copy import deepcopy
import simplejson as json
from collections import defaultdict

import wallet
from qrlcore.CreateGenesisBlock import CreateGenesisBlock
import merkle
from merkle import sha256
import helper
from block import Block
from transaction import SimpleTransaction
from decimal import Decimal
from qrlcore import transaction


class Chain:
    def __init__(self, state):
        self.state = state
        self.version_number = config.dev.version_number
        self.transaction_pool = []
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
        self.stake_validator_latency = defaultdict(dict)

        self.chain_dat_filename = os.path.join(config.user.data_path, config.dev.mnemonic_filename)

    @staticmethod
    def get_base_dir():
        tmp_path = os.path.join(config.user.data_path, config.dev.chain_file_directory)
        if not os.path.isdir(tmp_path):
            try:
                os.makedirs(tmp_path)
            except Exception as e:
                logger.error("Failed to create directory: %s - %s", tmp_path, e)
                sys.exit(1)

        return tmp_path + os.sep


    def initialize(self):
        logger.info('QRL blockchain ledger %s', self.version_number)
        logger.info('loading db')
        logger.info('loading wallet')

        self.wallet.f_load_winfo()

        logger.info('mining/staking address %s', self.mining_address)

    def validate_reboot(self, hash, nonce):
        reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]
        try:
            reboot_data_db = self.state.db.get('reboot_data')
            reboot_data = reboot_data_db
        except:
            pass

        if reboot_data[1] >= nonce:  # already used
            msg = 'nonce in db ' + str(reboot_data[1])
            msg += '\nnonce provided ' + str(nonce)
            return None, msg

        reboot_data[1] = nonce
        output = hash
        for i in range(0, reboot_data[1]):
            output = sha256(output)

        if output != reboot_data[0]:
            msg = 'expected hash ' + str(reboot_data[0])
            msg += '\nhash found ' + str(output)
            msg += '\nnonce provided ' + str(nonce) + "\n"
            return None, msg
        # reboot_data[1] += 1
        # self.state.db.put('reboot_data', reboot_data)

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

        return json.dumps(
            {'hash': output, 'nonce': reboot_data[1], 'blocknumber': int(blocknumber)}), "Reboot Initiated\r\n"

    def get_sv(self, terminator):
        for s in self.state.stake_list_get():
            if terminator in s[1]:
                return s[0]

        return None

    def reveal_to_terminator(self, reveal, blocknumber, add_loop=0):
        tmp = sha256(reveal)
        epoch = blocknumber // config.dev.blocks_per_epoch
        for _ in range(blocknumber - (epoch * config.dev.blocks_per_epoch) + add_loop):
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

        target_chain = (target_chain - 1) % (config.dev.hashchain_nums - 1)  # 1 Primary hashchain size

        return hashchain[-1], hashchain[target_chain]

    def select_winners(self, reveals, topN=1, blocknumber=None, block=None, seed=None):
        winners = None
        if not seed:
            logger.info('Exception raised due to Seed is None')
            raise Exception
        if blocknumber:
            winners = heapq.nsmallest(topN, reveals, key=lambda reveal: self.score(
                stake_address=self.get_sv(self.reveal_to_terminator(reveal, blocknumber, add_loop=1)),
                reveal_one=reveal,
                balance=self.block_chain_buffer.get_st_balance(
                    self.get_sv(self.reveal_to_terminator(reveal, blocknumber, add_loop=1)), blocknumber),
                seed=seed))  # blocknumber+1 as we have one extra hash for the reveal
            return winners

        winners = heapq.nsmallest(topN, reveals, key=lambda reveal: reveal[4])  # reveal[4] is score
        winners_dict = {}
        for winner in winners:
            winners_dict[winner[3]] = winner  # winner[3] is reveal_one
        return winners_dict

    @staticmethod
    def score(stake_address, reveal_one, balance=0, seed=None, verbose=False):
        if not seed:
            logger.info('Exception Raised due to seed none in score fn')
            raise Exception

        if not balance:
            logger.info(' balance 0 so score none ')
            logger.info(' stake_address %s', stake_address)
            return None

        reveal_one_number = int(reveal_one, 16)
        score = (Decimal(config.dev.N) - (Decimal(reveal_one_number | seed).log10() / Decimal(2).log10())) / Decimal(
            balance)

        if verbose:
            logger.info('Score - %f', score)
            logger.info('reveal_one - %ld', reveal_one_number)
            logger.info('seed - %ld', seed)
            logger.info('balance - %ld', balance)

        return score

    def update_pending_tx_pool(self, tx, peer):
        if len(self.pending_tx_pool) >= config.dev.blocks_per_epoch:
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
    def create_stake_block(self, hashchain_hash, reveal_list, vote_hashes, last_block_number):

        t_pool2 = copy.deepcopy(self.transaction_pool)

        del self.transaction_pool[:]
        curr_epoch = int((last_block_number + 1) / config.dev.blocks_per_epoch)
        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        d = defaultdict(int)

        for tx in t_pool2:
            if self.block_chain_buffer.pubhashExists(tx.txfrom, tx.pubhash, last_block_number + 1):
                continue
            if tx.subtype == transaction.TX_SUBTYPE_STAKE:
                if tx.epoch != curr_epoch:
                    logger.warning('Skipping st as epoch mismatch, CreateBlock()')
                    logger.warning('Expected st epoch : %s', curr_epoch)
                    logger.warning('Found st epoch : %s', tx.epoch)
                    continue
                balance = 0
                for st in self.block_chain_buffer.next_stake_list_get(last_block_number + 1):
                    if st[1] == tx.hash:
                        balance = st[-1]
                        break
                # balance>0 only in case 1st st txn without first_hash done
                if not (balance > 0 or last_block_number == 0):
                    if tx.first_hash:
                        continue
            self.add_tx_to_pool(tx)
            d[tx.txfrom] += 1
            tx.nonce = self.block_chain_buffer.get_stxn_state(last_block_number + 1, tx.txfrom)[0] + d[tx.txfrom]
            if tx.txfrom == self.mining_address:
                tx.nonce += 1

        # create the block..
        block_obj = self.m_create_block(hashchain_hash, reveal_list, vote_hashes, last_block_number)

        # reset the pool back
        self.transaction_pool = copy.deepcopy(t_pool2)

        return block_obj

    # return a sorted list of txhashes from transaction_pool, sorted by timestamp from block n
    # (actually from start of transaction_pool) to time, then ordered by txhash.
    def sorted_tx_pool(self, timestamp=None):
        if timestamp is None:
            timestamp = time()
        pool = copy.deepcopy(self.transaction_pool)
        trimmed_pool = []
        end_time = timestamp
        for tx in pool:
            if self.txhash_timestamp[self.txhash_timestamp.index(tx.txhash) + 1] <= end_time:
                trimmed_pool.append(tx.txhash)

        trimmed_pool.sort()

        if not trimmed_pool:
            return False

        return trimmed_pool

    # merkle tree root hash of tx from pool for next POS block
    @staticmethod
    def merkle_tx_hash(hashes):
        if len(hashes) == 64:  # if len = 64 then it is a single hash string rather than a list..
            return hashes
        j = int(ceil(log(len(hashes), 2)))
        l_array = [hashes]
        for x in range(j):
            next_layer = []
            i = len(l_array[x]) % 2 + len(l_array[x]) / 2
            z = 0
            for _ in range(i):
                if len(l_array[x]) == z + 1:
                    next_layer.append(l_array[x][z])
                else:
                    next_layer.append(sha256(l_array[x][z] + l_array[x][z + 1]))
                z += 2
            l_array.append(next_layer)

        return ''.join(l_array[-1])

    # return closest hash in numerical terms to merkle root hash of all the supplied hashes..

    def closest_hash(self, list_hash):

        if isinstance(list_hash, list):
            if len(list_hash) == 1:
                return False, False
        if isinstance(list_hash, str):
            if len(list_hash) == 64:
                return False, False

        list_hash.sort()

        root = self.merkle_tx_hash(list_hash)

        p = []
        for l in list_hash:
            p.append(int(l, 16))

        closest = self.cl(int(root, 16), p)

        return ''.join(list_hash[p.index(closest)]), root

    # return closest number in a hexlified list

    def cl_hex(self, one, many):

        p = []
        for l in many:
            p.append(int(l, 16))

        return many[p.index(self.cl(int(one, 16), p))]

    # return closest number in a list..
    @staticmethod
    def cl(one, many):
        return min(many, key=lambda x: abs(x - one))

    def is_stake_banned(self, stake_address):
        if stake_address in self.stake_ban_list:
            epoch_diff = (self.height() / config.dev.blocks_per_epoch) - (
                self.stake_ban_block[stake_address] / config.dev.blocks_per_epoch)
            if self.height() - self.stake_ban_block[stake_address] > 10 or epoch_diff > 0:
                logger.info('Stake removed from ban list')
                del self.stake_ban_block[stake_address]
                self.stake_ban_list.remove(stake_address)
                return False
            return True

        return False

    # create a snapshot of the transaction pool to account for network traversal time (probably less than 300ms, but let's give a window of 1.5 seconds).
    # returns: list of merkle root hashes of the tx pool over last 1.5 seconds
    def pos_block_pool(self, n=1.5):
        timestamp = time()
        start_time = timestamp - n

        x = self.sorted_tx_pool(start_time)
        y = self.sorted_tx_pool(timestamp)
        if not y:  # if pool is empty -> return sha256 null
            return [sha256('')], [[]]
        elif x == y:  # if the pool isnt empty but there is no difference then return the only merkle hash possible..
            return [self.merkle_tx_hash(y)], [y]
        else:  # there is a difference in contents of pool over last 1.5 seconds..
            merkle_hashes = []
            txhashes = []
            if not x:
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
    @staticmethod
    def pos_block_selector(seed, n):
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

    def search_telnet(self, txcontains, islong=1):
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
                if islong == 0: tx_list.append('<tx:txhash> ' + tx.txhash + ' <transaction_pool>')
                if islong == 1: tx_list.append(helper.json_print_telnet(tx))

        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains or tx.txto in hrs_list:
                    # logger.info(( txcontains, 'found in block',str(block.blockheader.blocknumber),'..'
                    if islong == 0: tx_list.append(
                        '<tx:txhash> ' + tx.txhash + ' <block> ' + str(block.blockheader.blocknumber))
                    if islong == 1: tx_list.append(helper.json_print_telnet(tx))
        return tx_list

    # used for port 80 api - produces JSON output of a specific tx hash, including status of tx, in a block or unconfirmed + timestampe of parent block

    def search_txhash(self, txhash):  # txhash is unique due to nonce.
        err = {'status': 'Error', 'error': 'txhash not found', 'method': 'txhash', 'parameter': txhash}
        for tx in self.transaction_pool:
            if tx.txhash == txhash:
                logger.info('%s found in transaction pool..', txhash)
                tx_new = copy.deepcopy(tx)
                tx_new.block = 'unconfirmed'
                tx_new.hexsize = len(helper.json_bytestream(tx_new))
                tx_new.status = 'ok'
                return helper.json_print_telnet(tx_new)

        txn_metadata = None
        try:
            txn_metadata = self.state.db.get(txhash)
        except:
            pass
        if not txn_metadata:
            logger.info('%s does not exist in memory pool or local blockchain..', txhash)
            return helper.json_print_telnet(err)

        tx = SimpleTransaction().json_to_transaction(txn_metadata[0])
        tx_new = copy.deepcopy(tx)
        tx_new.block = txn_metadata[1]
        tx_new.timestamp = txn_metadata[2]
        tx_new.confirmations = self.m_blockheight() - txn_metadata[1]
        tx_new.hexsize = len(helper.json_bytestream(tx_new))
        tx_new.amount = tx_new.amount / 100000000.000000000
        tx_new.fee = tx_new.fee / 100000000.000000000
        logger.info((txhash, 'found in block', str(txn_metadata[1]), '..'))
        tx_new.status = 'ok'
        return helper.json_print_telnet(tx_new)

    def basic_info(self, address):
        addr = {}

        if not self.state.state_address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return helper.json_print_telnet(addr)

        nonce, balance, _ = self.state.state_get_address(address)
        addr['state'] = {}
        addr['state']['address'] = address
        addr['state']['balance'] = balance / 100000000.000000000
        addr['state']['nonce'] = nonce
        addr['state']['transactions'] = self.state.state_get_txn_count(address)
        addr['status'] = 'ok'
        return helper.json_print_telnet(addr)

    # used for port 80 api - produces JSON output reporting every transaction for an address, plus final balance..

    def search_address(self, address):

        addr = {'transactions': {}}

        txnhash_added = set()

        if not self.state.state_address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return helper.json_print_telnet(addr)

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

        addr['transactions'] = []
        for tx in self.transaction_pool:
            if tx.txto == address or tx.txfrom == address:
                logger.info((address, 'found in transaction pool'))

                tmp_txn = {'txhash': tx.txhash,
                           'block': 'unconfirmed',
                           'amount': tx.amount / 100000000.000000000,
                           'fee': tx.fee / 100000000.000000000,
                           'nonce': tx.nonce,
                           'ots_key': tx.ots_key,
                           'txto': tx.txto,
                           'txfrom': tx.txfrom,
                           'timestamp': 'unconfirmed'}

                addr['transactions'].append(tmp_txn)
                txnhash_added.add(tx.txhash)

        my_txn = []
        try:
            my_txn = self.state.db.get('txn_' + address)
        except:
            pass

        for txn_hash in my_txn:
            txn_metadata = self.state.db.get(txn_hash)
            tx = SimpleTransaction().json_to_transaction(txn_metadata[0])
            if (tx.txto == address or tx.txfrom == address) and tx.txhash not in txnhash_added:
                logger.info((address, 'found in block ', str(txn_metadata[1]), '..'))
                tmp_txn = {}
                tmp_txn['txhash'] = tx.txhash
                tmp_txn['block'] = txn_metadata[1]
                tmp_txn['timestamp'] = txn_metadata[2]
                tmp_txn['amount'] = tx.amount / 100000000.000000000
                tmp_txn['fee'] = tx.fee / 100000000.000000000
                tmp_txn['nonce'] = tx.nonce
                tmp_txn['ots_key'] = tx.ots_key
                tmp_txn['txto'] = tx.txto
                tmp_txn['txfrom'] = tx.txfrom
                addr['transactions'].append(tmp_txn)
                txnhash_added.add(tx.txhash)

        if len(addr['transactions']) > 0:
            addr['state']['transactions'] = len(addr['transactions'])

        if addr == {'transactions': {}}:
            addr = {'status': 'error', 'error': 'address not found', 'method': 'address', 'parameter': address}
        else:
            addr['status'] = 'ok'

        return helper.json_print_telnet(addr)

    def last_unconfirmed_tx(self, n=1):
        addr = {}
        addr['transactions'] = {}

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': n}

        try:
            n = int(n)
        except:
            return helper.json_print_telnet(error)

        if n <= 0 or n > 20:
            return helper.json_print_telnet(error)
        addr['transactions'] = []
        if len(self.transaction_pool) != 0:
            if n - len(self.transaction_pool) >= 0:  # request bigger than tx in pool
                z = len(self.transaction_pool)
                n = n - len(self.transaction_pool)
            elif n - len(self.transaction_pool) <= 0:  # request smaller than tx in pool..
                z = n
                n = 0

            for tx in reversed(self.transaction_pool[-z:]):
                tmp_txn = {'txhash': tx.txhash,
                           'block': 'unconfirmed',
                           'timestamp': 'unconfirmed',
                           'amount': tx.amount / 100000000.000000000,
                           'type': tx.type}

                addr['transactions'].append(tmp_txn)

        addr['status'] = 'ok'
        return helper.json_print_telnet(addr)

    # return json info on last n tx in the blockchain

    def last_tx(self, n=1):

        addr = {}
        addr['transactions'] = {}

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': n}

        try:
            n = int(n)
        except:
            return helper.json_print_telnet(error)

        if n <= 0 or n > 20:
            return helper.json_print_telnet(error)
        addr['transactions'] = []
        if len(self.transaction_pool) != 0:
            if n - len(self.transaction_pool) >= 0:  # request bigger than tx in pool
                z = len(self.transaction_pool)
                n = n - len(self.transaction_pool)
            elif n - len(self.transaction_pool) <= 0:  # request smaller than tx in pool..
                z = n
                n = 0

            for tx in reversed(self.transaction_pool[-z:]):
                tmp_txn = {}
                tmp_txn['txhash'] = tx.txhash
                tmp_txn['block'] = 'unconfirmed'
                tmp_txn['timestamp'] = 'unconfirmed'
                tmp_txn['amount'] = tx.amount / 100000000.000000000
                tmp_txn['type'] = tx.type
                addr['transactions'].append(tmp_txn)

            if n == 0:
                addr['status'] = 'ok'
                return helper.json_print_telnet(addr)

        last_txn = self.state.db.get('last_txn')

        for tx_meta in reversed(last_txn):
            tx = SimpleTransaction().json_to_transaction(tx_meta[0])
            tmp_txn = {}
            tmp_txn['txhash'] = tx.txhash
            tmp_txn['block'] = tx_meta[1]
            tmp_txn['timestamp'] = tx_meta[2]
            tmp_txn['amount'] = tx.amount / 100000000.000000000
            tmp_txn['type'] = tx.type
            addr['transactions'].append(tmp_txn)
            n -= 1
            if n == 0:
                addr['status'] = 'ok'
                return helper.json_print_telnet(addr)

        error['error'] = 'txnhash not found'
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

        if not self.state.state_uptodate(self.m_blockheight()):
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

        lb = []
        beginning = self.height() - n
        for blocknum in range(self.height(), beginning - 1, -1):
            block = self.m_get_block(blocknum)
            lb.append(block)

        last_blocks = {}
        last_blocks['blocks'] = []
        i = 0
        for block in lb[1:]:
            i += 1
            tmp_block = {}
            tmp_block['blocknumber'] = block.blockheader.blocknumber
            tmp_block['block_reward'] = block.blockheader.block_reward / 100000000.00000000
            tmp_block['blocknumber'] = block.blockheader.blocknumber
            tmp_block['blockhash'] = block.blockheader.prev_blockheaderhash
            tmp_block['timestamp'] = block.blockheader.timestamp
            tmp_block['block_interval'] = block.blockheader.timestamp - lb[i - 1].blockheader.timestamp
            last_blocks['blocks'].append(tmp_block)

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
        stakers = {'status': 'ok',
                   'stake_list': []}

        for s in self.state.stake_list_get():
            tmp_stakers = {'address': s[0],
                           'balance': self.state.state_balance(s[0]) / 100000000.00000000,
                           'hash_terminator': s[1],
                           'nonce': s[2]}

            stakers['stake_list'].append(tmp_stakers)

        return helper.json_print_telnet(stakers)

    def next_stakers(self, data=None):
        # (stake -> address, hash_term, nonce)
        next_stakers = {}
        next_stakers['status'] = 'ok'
        next_stakers['stake_list'] = []
        for s in self.state.next_stake_list_get():
            tmp_stakers = {}
            tmp_stakers['address'] = s[0]
            tmp_stakers['balance'] = self.state.state_balance(s[0]) / 100000000.00000000
            tmp_stakers['hash_terminator'] = s[1]
            tmp_stakers['nonce'] = s[2]
            next_stakers['stake_list'].append(tmp_stakers)

        return helper.json_print_telnet(next_stakers)

    @staticmethod
    def exp_win(data=None):
        # TODO: incomplete
        ew = {}
        ew['status'] = 'ok'
        ew['expected_winner'] = {}

        return helper.json_print_telnet(ew)

    def stake_reveal_ones(self, data=None):

        sr = {}
        sr['status'] = 'ok'
        sr['reveals'] = {}

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

    def search(self, txcontains, islong=1):
        for tx in self.transaction_pool:
            if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
                logger.info((txcontains, 'found in transaction pool..'))
                if islong == 1: helper.json_print(tx)
        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
                    logger.info((txcontains, 'found in block', str(block.blockheader.blocknumber), '..'))
                    if islong == 0: logger.info(('<tx:txhash> ' + tx.txhash))
                    if islong == 1: helper.json_print(tx)
        return

    def f_read_chain(self, epoch):
        baseDir = self.get_base_dir()
        delimiter = config.dev.binary_file_delimiter
        block_list = []
        if os.path.isfile(baseDir + 'chain.da' + str(epoch)) is False:
            if epoch != 0:
                return []
            logger.info('Creating new chain file')
            block_list.append(CreateGenesisBlock(self))
            return block_list

        try:
            with open(baseDir + 'chain.da' + str(epoch), 'rb') as myfile:
                jsonBlock = StringIO()
                tmp = ""
                count = 0
                offset = 0
                while True:
                    chars = myfile.read(config.dev.chain_read_buffer_size)
                    for char in chars:
                        offset += 1
                        if count > 0 and char != delimiter[count]:
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
                            jsonBlock = bz2.decompress(compressedBlock)
                            block = Block.from_json(jsonBlock)
                            self.update_block_metadata(block.blockheader.blocknumber, pos, len(compressedBlock))
                            block_list.append(block)
                            jsonBlock = StringIO()
                            continue
                        jsonBlock.write(char)
                    if len(chars) < config.dev.chain_read_buffer_size:
                        break
        except Exception as e:
            logger.error('IO error %s', e)
            return []

        gc.collect()
        return block_list

    def update_block_metadata(self, blocknumber, blockPos, blockSize):
        self.state.db.db.Put('block_' + str(blocknumber), str(blockPos) + ',' + str(blockSize))

    def update_last_tx(self, block):
        if len(block.transactions) == 0:
            return
        last_txn = []
        try:
            last_txn = self.state.db.get('last_txn')
        except:
            pass
        for txn in block.transactions[-20:]:
            if txn.subtype == transaction.TX_SUBTYPE_TX:
                last_txn.insert(0,
                                [txn.transaction_to_json(), block.blockheader.blocknumber, block.blockheader.timestamp])
        del last_txn[20:]
        self.state.db.put('last_txn', last_txn)

    def update_wallet_tx_metadata(self, addr, new_txhash):
        try:
            txhash = self.state.db.get('txn_' + addr)
        except Exception:
            txhash = []
        txhash.append(new_txhash)
        self.state.db.put('txn_' + addr, txhash)

    def update_txn_count(self, txto, txfrom):
        last_count = self.state.state_get_txn_count(txto)
        self.state.db.put('txn_count_' + txto, last_count + 1)
        last_count = self.state.state_get_txn_count(txfrom)
        self.state.db.put('txn_count_' + txfrom, last_count + 1)

    def update_tx_metadata(self, block):
        if len(block.transactions) == 0:
            return

        for txn in block.transactions:
            if txn.subtype == transaction.TX_SUBTYPE_TX:
                self.state.db.put(txn.txhash,
                                  [txn.transaction_to_json(), block.blockheader.blocknumber,
                                   block.blockheader.timestamp])
                self.update_wallet_tx_metadata(txn.txfrom, txn.txhash)
                self.update_wallet_tx_metadata(txn.txto, txn.txhash)
                self.update_txn_count(txn.txto, txn.txfrom)

    def f_write_m_blockchain(self):
        baseDir = self.get_base_dir()

        blocknumber = self.m_blockchain[-1].blockheader.blocknumber
        suffix = int(blocknumber // config.dev.blocks_per_chain_file)
        writeable = self.m_blockchain[-config.dev.disk_writes_after_x_blocks:]
        logger.info('Appending data to chain')

        with open(baseDir + 'chain.da' + str(suffix), 'ab') as myfile:
            for block in writeable:
                jsonBlock = helper.json_bytestream(block)
                compressedBlock = bz2.compress(jsonBlock, config.dev.compression_level)
                pos = myfile.tell()
                blockSize = len(compressedBlock)
                self.update_block_metadata(block.blockheader.blocknumber, pos, blockSize)
                myfile.write(compressedBlock)
                myfile.write(config.dev.binary_file_delimiter)

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

        if len(self.m_blockchain) < config.dev.blocks_per_chain_file:
            return self.m_blockchain

        epoch = 1
        baseDir = self.get_base_dir()
        while os.path.isfile(baseDir + 'chain.da' + str(epoch)):
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
        baseDir = self.get_base_dir()
        epoch = int(blocknum // config.dev.blocks_per_chain_file)
        with open(baseDir + 'chain.da' + str(epoch), 'rb') as f:
            pos_size = self.state.db.db.Get('block_' + str(blocknum))
            pos, size = pos_size.split(',')
            pos = int(pos)
            size = int(size)
            f.seek(pos)
            jsonBlock = bz2.decompress(f.read(size))
            block = Block.from_json(jsonBlock)
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

    def m_create_block(self, nonce, reveal_list=None, vote_hashes=None, last_block_number=-1):
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
            else:
                logger.info('last block failed state/stake checks, removed from chain')
                self.state.state_validate_tx_pool(self)
                return False
        else:
            logger.info('m_add_block failed - block failed validation.')
            return False
        self.m_f_sync_chain()
        return True

    def m_remove_last_block(self):
        if not self.m_blockchain:
            self.m_read_chain()
        self.m_blockchain.pop()

    def m_blockheight(self):
        # return len(self.m_read_chain()) - 1
        return self.height()

    def height(self):
        if len(self.m_blockchain):
            return self.m_blockchain[-1].blockheader.blocknumber
        return -1

    def m_info_block(self, n):
        if n > self.m_blockheight():
            logger.info('No such block exists yet..')
            return False
        b = self.m_get_block(n)
        logger.info(('Block: ', b, str(b.blockheader.blocknumber)))
        logger.info(('Blocksize, ', str(len(helper.json_bytestream(b)))))
        logger.info(('Number of transactions: ', str(len(b.transactions))))
        logger.info(('Validates: ', b.validate_block(self)))

    def m_f_sync_chain(self):
        if (self.m_blockchain[-1].blockheader.blocknumber + 1) % config.dev.disk_writes_after_x_blocks == 0:
            self.f_write_m_blockchain()
        return

    def m_verify_chain(self, verbose=0):
        for block in self.m_read_chain()[1:]:
            if block.validate_block(self) is False:
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
                logger.info(('block failed:', block.blockheader.blocknumber))
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

    def remove_tx_from_pool(self, tx_class_obj):
        self.transaction_pool.remove(tx_class_obj)
        self.txhash_timestamp.pop(self.txhash_timestamp.index(tx_class_obj.txhash) + 1)
        self.txhash_timestamp.remove(tx_class_obj.txhash)

    def show_tx_pool(self):
        return self.transaction_pool

    def remove_tx_in_block_from_pool(self, block_obj):
        for tx in block_obj.transactions:
            for txn in self.transaction_pool:
                if tx.txhash == txn.txhash:
                    self.remove_tx_from_pool(txn)

    def flush_tx_pool(self):
        del self.transaction_pool[:]

    def validate_tx_pool(self):  # invalid transactions are auto removed from pool..
        for transaction in self.transaction_pool:
            if transaction.validate_tx() is False:
                self.remove_tx_from_pool(transaction)
                logger.info(('invalid tx: ', transaction, 'removed from pool'))

        return True

    def create_my_tx(self, txfrom, txto, amount, fee=0):
        if isinstance(txto, int):
            txto = self.my[txto][0]

        xmss = self.my[txfrom][1]
        tx_state = self.block_chain_buffer.get_stxn_state(self.block_chain_buffer.height() + 1, xmss.address)
        tx = SimpleTransaction().create(tx_state=tx_state,
                                        txto=txto,
                                        amount=amount,
                                        xmss=xmss,
                                        fee=fee)

        if tx and tx.state_validate_tx(tx_state=tx_state, transaction_pool=self.transaction_pool):
            self.add_tx_to_pool(tx)
            self.wallet.f_save_winfo()  # need to keep state after tx ..use self.wallet.info to store index..far faster than loading the 55mb self.wallet..
            return tx

        return False


class BlockBuffer:
    def __init__(self, block, stake_reward, chain, seed, balance):  # , prev_seed):
        self.block = block
        self.stake_reward = stake_reward
        self.score = self.block_score(chain, seed, balance)

    def block_score(self, chain, seed, balance):
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
        self.stxn_state = {}  # key address, value [nonce, balance, pubhash]
        self.next_seed = None  ##
        self.hash_chain = None  ##

    def set_next_seed(self, winning_reveal, prev_seed):
        self.next_seed = sha256(winning_reveal + str(prev_seed))

    @staticmethod
    def tx_to_list(txn_dict):
        tmp_sl = []
        for txfrom in txn_dict:
            st = txn_dict[txfrom]
            if not st[3]:  # rejecting ST having first_hash None
                continue
            tmp_sl.append(st)
        return tmp_sl

    def update(self, state, parent_state_buffer, block):
        # epoch mod, helps you to know if its the new epoch
        epoch_mod = block.blockheader.blocknumber % config.dev.blocks_per_epoch

        self.stake_list = deepcopy(parent_state_buffer.stake_list)
        self.next_stake_list = deepcopy(parent_state_buffer.next_stake_list)
        # TODO filter all next_stake_list with first_reveal None
        # Before adding_block, check if the stake_selector is in stake_list
        self.set_next_seed(block.blockheader.hash, parent_state_buffer.next_seed)
        self.hash_chain = deepcopy(parent_state_buffer.hash_chain)
        self.stxn_state = deepcopy(parent_state_buffer.stxn_state)

        if not epoch_mod:  # State belongs to first block of next epoch
            self.stake_list = self.next_stake_list
            self.next_stake_list = {}

            tmp_sl = self.tx_to_list(self.stake_list)

            self.stake_list = {}
            for st in tmp_sl:
                self.stake_list[st[0]] = st

        if epoch_mod == config.dev.blocks_per_epoch - 1:
            tmp_sl = self.tx_to_list(self.next_stake_list)

            self.next_seed = state.calc_seed(tmp_sl, verbose=False)

        self.update_stake_list(block)
        self.update_next_stake_list(block)
        self.update_stxn_state(block, state)

    def update_stxn_state(self, block, state):
        ignore_addr = set()
        for tx in block.transactions:
            ignore_addr.add(tx.txfrom)  # list of addresses that needs to be included in the buffer

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                ignore_addr.add(tx.txto)
                if tx.txto not in self.stxn_state:
                    self.stxn_state[tx.txto] = state.state_get_address(tx.txto)

            if tx.txfrom not in self.stxn_state:
                self.stxn_state[tx.txfrom] = state.state_get_address(tx.txfrom)

            self.stxn_state[tx.txfrom][2].append(tx.pubhash)

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                self.stxn_state[tx.txfrom][1] -= tx.amount

            if tx.subtype in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                self.stxn_state[tx.txto][1] += tx.amount

            if tx.txfrom in self.stxn_state:
                if self.stxn_state[tx.txfrom][0] > tx.nonce:
                    continue

            self.stxn_state[tx.txfrom][0] = tx.nonce

        stxn_state_keys = self.stxn_state.keys()
        for addr in stxn_state_keys:
            if addr in ignore_addr:
                continue
            addr_list = state.state_get_address(addr)
            if not addr_list:
                continue

            if self.stxn_state[addr][1] == addr_list[1] and self.stxn_state[addr][2] == addr_list[2]:
                del self.stxn_state[addr]

    def update_next_stake_list(self, block):
        for st in block.transactions:
            if st.subtype != transaction.TX_SUBTYPE_STAKE:
                continue
            if st.txfrom in self.next_stake_list and self.next_stake_list[st.txfrom][3]:
                continue
            self.next_stake_list[st.txfrom] = [st.txfrom, st.hash, 0, st.first_hash, st.balance]

    def update_stake_list(self, block):
        stake_selector = block.blockheader.stake_selector
        if stake_selector not in self.stake_list:
            logger.error('Error Stake selector not found stake_list of block buffer state')
            raise Exception
        self.stake_list[stake_selector][2] += 1  # Update Nonce


class ChainBuffer:
    def __init__(self, chain):
        self.chain = chain
        self.state = self.chain.state
        self.wallet = self.chain.wallet
        self.blocks = dict()
        self.strongest_chain = dict()
        self.headerhashes = dict()
        self.size = config.dev.reorg_limit
        self.pending_blocks = dict()
        self.epoch = max(0, self.chain.height()) // config.dev.blocks_per_epoch  # Main chain epoch
        self.my = dict()
        self.my[self.epoch] = deepcopy(self.chain.my)
        self.epoch_seed = None
        self.hash_chain = dict()
        self.hash_chain[self.epoch] = self.chain.my[0][1].hc
        self.tx_buffer = dict()  # maintain the list of tx transaction that has been confirmed in buffer
        if self.chain.height() > 0:
            self.epoch = int(self.chain.m_blockchain[-1].blockheader.blocknumber / config.dev.blocks_per_epoch)

    def get_st_balance(self, stake_address, blocknumber):
        if stake_address is None:
            logger.info('stake address should not be none')
            raise Exception

        if blocknumber - 1 == self.chain.height():
            for st in self.state.stake_list_get():
                if stake_address == st[0]:
                    return st[-1]
            logger.info('Blocknumber not found')
            return None

        if blocknumber - 1 not in self.strongest_chain:
            logger.info('Blocknumber not in strongest chain')
            return None

        if blocknumber % config.dev.blocks_per_epoch == 0:
            return self.strongest_chain[blocknumber - 1][1].next_stake_list[stake_address][-1]

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
        epoch = int(blocknumber // config.dev.blocks_per_epoch)
        return self.hash_chain[epoch]

    def update_hash_chain(self, blocknumber):
        epoch = int((blocknumber + 1) // config.dev.blocks_per_epoch)
        logger.info('Created new hash chain')
        new_my = deepcopy(self.my[epoch - 1])
        new_my[0][1].hashchain(epoch=epoch)
        self.my[epoch] = new_my
        self.hash_chain[epoch] = new_my[0][1].hc
        gc.collect()

    def add_txns_buffer(self):
        if len(self.blocks) == 0:
            return
        del self.tx_buffer
        self.tx_buffer = {}

        min_blocknum = self.chain.height() + 1
        max_blocknum = max(self.strongest_chain.keys())

        for blocknum in range(min_blocknum, max_blocknum + 1):
            block_state_buffer = self.strongest_chain[blocknum]
            block = block_state_buffer[0].block

            self.tx_buffer[blocknum] = []

            for tx in block.transactions:
                self.tx_buffer[blocknum].append(tx.txhash)

    def add_block_mainchain(self, block, verify_block_reveal_list=True, validate=True):
        # TODO : minimum block validation in unsynced state
        blocknum = block.blockheader.blocknumber
        epoch = int(blocknum // config.dev.blocks_per_epoch)
        prev_headerhash = block.blockheader.prev_blockheaderhash

        if blocknum <= self.chain.height():
            return

        if blocknum - 1 == self.chain.height():
            if prev_headerhash != self.chain.m_blockchain[-1].blockheader.headerhash:
                logger.info('prev_headerhash of block doesnt match with headerhash of m_blockchain')
                return
        elif blocknum - 1 > 0:
            if blocknum - 1 not in self.blocks or prev_headerhash not in self.headerhashes[blocknum - 1]:
                logger.info('No block found in buffer that matches with the prev_headerhash of received block')
                return

        if validate:
            if not self.chain.m_add_block(block, verify_block_reveal_list):
                logger.info(("Failed to add block by m_add_block, re-requesting the block #", blocknum))
                return
        else:
            if self.state.state_add_block(self.chain, block) is True:
                self.chain.m_blockchain.append(block)

        block_left = config.dev.blocks_per_epoch - (
            block.blockheader.blocknumber - (block.blockheader.epoch * config.dev.blocks_per_epoch))

        self.add_txns_buffer()
        if block_left == 1:  # As state_add_block would have already moved the next stake list to stake_list
            self.epoch_seed = self.state.calc_seed(self.state.stake_list_get(), verbose=False)
            self.my[epoch + 1] = self.chain.my
            self.hash_chain[epoch + 1] = self.chain.my[0][1].hc
            if epoch in self.my:
                del self.my[epoch]
        else:
            self.epoch_seed = sha256(block.blockheader.hash + str(self.epoch_seed))

        self.chain.update_last_tx(block)
        self.chain.update_tx_metadata(block)
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
                logger.warning('Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return
        else:
            if blocknum - 1 not in self.blocks or prev_headerhash not in self.headerhashes[blocknum - 1]:
                logger.warning('Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return

        if blocknum not in self.blocks:
            self.blocks[blocknum] = []
            self.headerhashes[blocknum] = []

        if headerhash in self.headerhashes[blocknum]:
            return 0

        if blocknum - self.size in self.strongest_chain:
            self.move_to_mainchain()

        stake_reward = {}

        state_buffer = StateBuffer()
        block_buffer = None
        if blocknum - 1 == self.chain.height():
            tmp_stake_list = self.state.stake_list_get()
            tmp_next_stake_list = self.state.next_stake_list_get()

            if blocknum % config.dev.blocks_per_epoch == 0:  # quick fix when a node starts, it already moved to next epoch stake list
                tmp_stake_list, tmp_next_stake_list = tmp_next_stake_list, tmp_stake_list

            if not self.state_validate_block(block, copy.deepcopy(tmp_stake_list), copy.deepcopy(tmp_next_stake_list)):
                logger.warning('State_validate_block failed inside chainbuffer #%d', block.blockheader.blocknumber)
                return

            if blocknum % config.dev.blocks_per_epoch == 0:  # quick fix swapping back values
                tmp_stake_list, tmp_next_stake_list = tmp_next_stake_list, tmp_stake_list

            for st in tmp_stake_list:
                state_buffer.stake_list[st[0]] = st

            for st in tmp_next_stake_list:
                state_buffer.next_stake_list[st[0]] = st
            block_buffer = BlockBuffer(block, stake_reward, self.chain, self.epoch_seed,
                                       self.get_st_balance(block.blockheader.stake_selector,
                                                           block.blockheader.blocknumber))
            state_buffer.set_next_seed(block.blockheader.hash, self.epoch_seed)
            state_buffer.update_stake_list(block)
            state_buffer.update_next_stake_list(block)
            state_buffer.update_stxn_state(block, self.state)
        else:
            parent_state_buffer = None
            parent_seed = None
            for block_state_buffer in self.blocks[blocknum - 1]:
                prev_block = block_state_buffer[0].block
                if prev_block.blockheader.headerhash == prev_headerhash:
                    parent_state_buffer = block_state_buffer[1]
                    parent_seed = block_state_buffer[1].next_seed
                    break

            if not self.state_validate_block(block, copy.deepcopy(
                    parent_state_buffer.tx_to_list(parent_state_buffer.stake_list)), copy.deepcopy(
                parent_state_buffer.tx_to_list(parent_state_buffer.next_stake_list))):
                logger.warning('State_validate_block failed inside chainbuffer #%d', block.blockheader.blocknumber)
                return
            block_buffer = BlockBuffer(block, stake_reward, self.chain, parent_seed,
                                       self.get_st_balance(block.blockheader.stake_selector,
                                                           block.blockheader.blocknumber))
            state_buffer.update(self.state, parent_state_buffer, block)
        self.blocks[blocknum].append([block_buffer, state_buffer])

        if len(self.strongest_chain) == 0 and self.chain.m_blockchain[-1].blockheader.headerhash == prev_headerhash:
            self.strongest_chain[blocknum] = [block_buffer, state_buffer]
            self.chain.update_tx_metadata(block)
        elif blocknum not in self.strongest_chain and self.strongest_chain[blocknum - 1][
            0].block.blockheader.headerhash == prev_headerhash:
            self.strongest_chain[blocknum] = [block_buffer, state_buffer]
            self.chain.update_tx_metadata(block)
        elif blocknum in self.strongest_chain:
            old_block_buffer = self.strongest_chain[blocknum][0]
            if old_block_buffer.block.blockheader.prev_blockheaderhash == block_buffer.block.blockheader.prev_blockheaderhash:
                if block_buffer.score < old_block_buffer.score:
                    self.strongest_chain[blocknum] = [block_buffer, state_buffer]
                    if blocknum + 1 in self.strongest_chain:
                        self.recalculate_strongest_chain(blocknum)

        self.headerhashes[blocknum].append(block.blockheader.headerhash)

        epoch = blocknum // config.dev.blocks_per_epoch
        next_epoch = (blocknum + 1) // config.dev.blocks_per_epoch
        if epoch != next_epoch:
            self.update_hash_chain(block.blockheader.blocknumber)

        self.add_txns_buffer()

        return True

    def state_validate_block(self, block, sl, next_sl):
        if block.blockheader.blocknumber % config.dev.blocks_per_epoch == 0:
            sl = next_sl
            next_sl = list()

        address_txn = dict()
        blocknumber = block.blockheader.blocknumber

        for tx in block.transactions:
            if tx.txfrom not in address_txn:
                address_txn[tx.txfrom] = self.get_stxn_state(blocknumber, tx.txfrom)
            if tx.subtype == transaction.TX_SUBTYPE_TX:
                if tx.txto not in address_txn:
                    address_txn[tx.txto] = self.get_stxn_state(blocknumber, tx.txto)

        found = False

        blocks_left = block.blockheader.blocknumber - (block.blockheader.epoch * config.dev.blocks_per_epoch)
        blocks_left = config.dev.blocks_per_epoch - blocks_left

        for s in sl:
            if block.blockheader.stake_selector == s[0]:
                found = True
                break

        if not found:
            logger.warning('stake selector not in stake_list_get')
            logger.warning('stake selector: %s', block.blockheader.stake_selector)
            return

        for tx in block.transactions:

            pubhash = tx.generate_pubhash(tx.pub)

            if tx.nonce != address_txn[tx.txfrom][0] + 1:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.subtype)
                logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, address_txn[tx.txfrom][0] + 1)
                for t in block.transactions:
                    logger.info('%s %s %s', t.subtype, t.txfrom, t.nonce)
                return False

            if pubhash in address_txn[tx.txfrom][2]:
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.subtype)
                return False

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                if address_txn[tx.txfrom][1] - tx.amount < 0:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s', address_txn[tx.txfrom][1], tx.amount)
                    return False

            elif tx.subtype == transaction.TX_SUBTYPE_STAKE:
                found = False
                for s in next_sl:
                    # already in the next stake list, ignore for staker list but update as usual the state_for_address..
                    if tx.txfrom == s[0]:
                        found = True
                        if s[3] is None and tx.first_hash is not None:
                            threshold_block = self.state.get_staker_threshold_blocknum(next_sl, s[0])
                            epoch_blocknum = config.dev.blocks_per_epoch - blocks_left
                            if epoch_blocknum >= threshold_block - 1:
                                s[3] = tx.first_hash

                        break

                    if not found:
                        next_sl.append([tx.txfrom, tx.hash, 0, tx.first_hash, tx.balance])

            address_txn[tx.txfrom][0] += 1

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                address_txn[tx.txfrom][1] -= tx.amount

            if tx.subtype in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                address_txn[tx.txto][1] = address_txn[tx.txto][1] + tx.amount

            address_txn[tx.txfrom][2].append(pubhash)

        return True

    def recalculate_strongest_chain(self, blocknum):
        if blocknum + 1 not in self.strongest_chain:
            return

        for i in range(blocknum + 1, max(self.strongest_chain) + 1):
            del self.strongest_chain[i]

        block = self.strongest_chain[blocknum][0].block
        prev_headerhash = block.blockheader.headerhash
        blocknum += 1
        block_state_buffer = self.get_strongest_block(blocknum, prev_headerhash)

        while block_state_buffer is not None:
            self.strongest_chain[blocknum] = block_state_buffer

            block_buffer = block_state_buffer[0]
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
            # return self.chain.m_blockchain[blocknum].blockheader.headerhash

        if blocknum not in self.strongest_chain:
            logger.info(('Blocknum : ', str(blocknum), ' not found in buffer'))
            return None

        return self.strongest_chain[blocknum][0].block.blockheader.headerhash

    def get_epoch_seed(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return int(str(self.epoch_seed), 16)
        if blocknumber - 1 not in self.strongest_chain:
            return None
        return int(str(self.strongest_chain[blocknumber - 1][1].next_seed), 16)

    def get_stxn_state(self, blocknumber, addr):
        if blocknumber - 1 == self.chain.height():
            return self.state.state_get_address(addr)

        if blocknumber - 1 not in self.strongest_chain:
            return None

        stateBuffer = self.strongest_chain[blocknumber - 1][1]

        if addr in stateBuffer.stxn_state:
            return deepcopy(stateBuffer.stxn_state[addr])

        return self.state.state_get_address(addr)

    def stake_list_get(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return self.state.stake_list_get()

        if blocknumber - 1 not in self.strongest_chain:
            logger.info('Stake list None')
            logger.info(('blocknumber #', blocknumber - 1, 'not found in strongest_chain'))
            return None

        stateBuffer = self.strongest_chain[blocknumber - 1][1]
        if blocknumber % config.dev.blocks_per_epoch == 0:
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
        logger.info(('=' * 40))
        for blocknum in range(min_block, max_block + 1):
            logger.info('Block number #%d', blocknum)
            for block_state_buffer in self.blocks[blocknum]:
                blockBuffer = block_state_buffer[0]
                block = blockBuffer.block
                logger.info((block.blockheader.headerhash, ' ', str(blockBuffer.score), ' ',
                             str(block.blockheader.block_reward)))
                logger.info((block.blockheader.hash, ' ', block.blockheader.stake_selector))
        logger.info(('=' * 40))

    def move_to_mainchain(self):
        blocknum = self.chain.height() + 1
        block = self.strongest_chain[blocknum][0].block
        if not self.state.state_add_block(self.chain, block):
            logger.info('last block failed state/stake checks, removed from chain')
            return False

        self.chain.m_blockchain.append(block)
        self.chain.remove_tx_in_block_from_pool(block)  # modify fn to keep transaction in memory till reorg
        self.chain.m_f_sync_chain()

        self.epoch_seed = self.strongest_chain[blocknum][1].next_seed

        del (self.blocks[blocknum])
        del (self.headerhashes[blocknum])
        del self.strongest_chain[blocknum]
        prev_epoch = int((blocknum - 1) // config.dev.blocks_per_epoch)
        self.epoch = int(blocknum // config.dev.blocks_per_epoch)
        if prev_epoch != self.epoch:
            if prev_epoch in self.my:
                del self.my[prev_epoch]
            if prev_epoch in self.hash_chain:
                del self.hash_chain[prev_epoch]

        self.chain.update_last_tx(block)
        self.chain.update_tx_metadata(block)
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
        logger.info(('Processing pending blocks', min_blocknum, max_blocknum))
        for blocknum in range(min_blocknum, max_blocknum + 1):
            for block in self.pending_blocks[blocknum]:
                self.add_block(block)
            del self.pending_blocks[blocknum]

    def pubhashExists(self, addr, pubhash, blocknumber):
        state_addr = self.get_stxn_state(blocknumber, addr)

        if state_addr is None:
            logger.info('-->> state_addr None not possible')
            return False

        if pubhash in state_addr[2]:
            return True

        return False
