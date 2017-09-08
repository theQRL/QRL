# coding=utf-8
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
from qrl.core import config, logger, transaction
from qrl.core.CreateGenesisBlock import CreateGenesisBlock
from qrl.core.ChainBuffer import ChainBuffer
from qrl.core.block import Block
from qrl.core.helper import json_print_telnet, json_bytestream, json_print
from qrl.core.transaction import SimpleTransaction, CoinBase
from qrl.core.wallet import Wallet
from qrl.crypto.hmac_drbg import GEN_range_bin
from qrl.crypto.misc import sha256, merkle_tx_hash, closest_number

__author__ = 'pete'

import gc

import bz2
from StringIO import StringIO
from time import time
from operator import itemgetter
from math import log, ceil
import heapq
import os, copy, sys
import simplejson as json
from collections import defaultdict
from decimal import Decimal


class Chain:
    def __init__(self, state):
        self.state = state
        self.version_number = config.dev.version_number
        self.transaction_pool = []
        self.txhash_timestamp = []
        self.m_blockchain = []

        self.wallet = Wallet(self, state)
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

    def initialize(self):
        logger.info('QRL blockchain ledger %s', self.version_number)
        logger.info('loading db')
        logger.info('loading wallet')

        self.wallet.f_load_winfo()

        logger.info('mining/staking address %s', self.mining_address)

    def validate_reboot(self, mhash, nonce):
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
        output = mhash
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
            logger.info('Score - %s', score)
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
        stake_validators_list = self.state.stake_validators_list
        for staker in stake_validators_list.sv_list:
            balance = self.state.state_balance(staker)
            sv_hash.write(staker + str(balance))
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
                epoch_blocknum = last_block_number - (curr_epoch * config.dev.blocks_per_epoch)

                # skip 1st st txn without tx.first_hash in case its beyond allowed epoch blocknumber
                if (not tx.first_hash) and epoch_blocknum >= config.dev.stake_before_x_blocks:
                    return False

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

    @staticmethod
    def closest_hash(list_hash):
        """
        returns the closest hash in numerical terms to merkle root hash of all the supplied hashes..
        :param list_hash:
        :return:
        """

        if isinstance(list_hash, list):
            if len(list_hash) == 1:
                return False, False
        if isinstance(list_hash, str):
            if len(list_hash) == 64:
                return False, False

        list_hash.sort()

        root = merkle_tx_hash(list_hash)

        p = []
        for l in list_hash:
            p.append(int(l, 16))

        closest = closest_number(int(root, 16), p)

        return ''.join(list_hash[p.index(closest)]), root

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

    def pos_block_pool(self, n=1.5):
        """
        create a snapshot of the transaction pool to account for network traversal time (probably less than 300ms, but let's give a window of 1.5 seconds).
        :param n:
        :return: list of merkle root hashes of the tx pool over last 1.5 seconds
        """
        timestamp = time()
        start_time = timestamp - n

        x = self.sorted_tx_pool(start_time)
        y = self.sorted_tx_pool(timestamp)
        if not y:  # if pool is empty -> return sha256 null
            return [sha256('')], [[]]
        elif x == y:  # if the pool isnt empty but there is no difference then return the only merkle hash possible..
            return [merkle_tx_hash(y)], [y]
        else:  # there is a difference in contents of pool over last 1.5 seconds..
            merkle_hashes = []
            txhashes = []
            if not x:
                merkle_hashes.append(sha256(''))
                x = []
                txhashes.append(x)
            else:
                merkle_hashes.append(merkle_tx_hash(x))
                txhashes.append(x)
            tmp_txhashes = x

            for tx in reversed(self.transaction_pool):
                if tx.txhash in y and tx.txhash not in x:
                    tmp_txhashes.append(tx.txhash)
                    tmp_txhashes.sort()
                    merkle_hashes.append(merkle_tx_hash(tmp_txhashes))
                    txhashes.append(tmp_txhashes)

            return merkle_hashes, txhashes

    @staticmethod
    def pos_block_selector(seed, n):
        """
        create the PRF selector sequence based upon a seed and number
        of stakers in list (temporary..there are better ways to do this
        with bigger seed value, but it works)
        :param seed:
        :param n:
        :return:
        """
        n_bits = int(ceil(log(n, 2)))
        prf = GEN_range_bin(seed, 1, 20000, 1)
        prf_range = []
        for z in prf:
            x = ord(z) >> 8 - n_bits
            if x < n:
                prf_range.append(x)
        return prf_range

    def pos_block_selector_n(self, seed, n, i):
        """
        return the POS staker list position for given seed at index, i
        :param seed:
        :param n:
        :param i:
        :return:
        """
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
                if islong == 1: tx_list.append(json_print_telnet(tx))

        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains or tx.txto in hrs_list:
                    # logger.info(( txcontains, 'found in block',str(block.blockheader.blocknumber),'..'
                    if islong == 0: tx_list.append(
                        '<tx:txhash> ' + tx.txhash + ' <block> ' + str(block.blockheader.blocknumber))
                    if islong == 1: tx_list.append(json_print_telnet(tx))
        return tx_list

    # used for port 80 api - produces JSON output of a specific tx hash, including status of tx, in a block or unconfirmed + timestampe of parent block

    def search_txhash(self, txhash):  # txhash is unique due to nonce.
        err = {'status': 'Error', 'error': 'txhash not found', 'method': 'txhash', 'parameter': txhash}
        for tx in self.transaction_pool:
            if tx.txhash == txhash:
                logger.info('%s found in transaction pool..', txhash)
                tx_new = copy.deepcopy(tx)
                tx_new.block = 'unconfirmed'
                tx_new.hexsize = len(json_bytestream(tx_new))
                tx_new.status = 'ok'
                return json_print_telnet(tx_new)

        try:
            txn_metadata = self.state.db.get(txhash)
        except:
            logger.info('%s does not exist in memory pool or local blockchain..', txhash)
            return json_print_telnet(err)

        json_tx = json.loads(txn_metadata[0])
        if json_tx['subtype'] == transaction.TX_SUBTYPE_TX:
            tx = SimpleTransaction().json_to_transaction(txn_metadata[0])
        elif json_tx['subtype'] == transaction.TX_SUBTYPE_COINBASE:
            tx = CoinBase().json_to_transaction(txn_metadata[0])
        tx_new = copy.deepcopy(tx)
        tx_new.block = txn_metadata[1]
        tx_new.timestamp = txn_metadata[2]
        tx_new.confirmations = self.m_blockheight() - txn_metadata[1]
        tx_new.hexsize = len(json_bytestream(tx_new))
        tx_new.amount = tx_new.amount / 100000000.000000000
        if json_tx['subtype'] == transaction.TX_SUBTYPE_TX:
            tx_new.fee = tx_new.fee / 100000000.000000000
        logger.info('%s found in block %s', txhash, str(txn_metadata[1]))
        tx_new.status = 'ok'
        return json_print_telnet(tx_new)

    def basic_info(self, address):
        addr = {}

        if not self.state.state_address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return json_print_telnet(addr)

        nonce, balance, _ = self.state.state_get_address(address)
        addr['state'] = {}
        addr['state']['address'] = address
        addr['state']['balance'] = balance / 100000000.000000000
        addr['state']['nonce'] = nonce
        addr['state']['transactions'] = self.state.state_get_txn_count(address)
        addr['status'] = 'ok'
        return json_print_telnet(addr)

    # used for port 80 api - produces JSON output reporting every transaction for an address, plus final balance..

    def search_address(self, address):

        addr = {'transactions': []}

        txnhash_added = set()

        if not self.state.state_address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return json_print_telnet(addr)

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

        tmp_transactions = []
        for tx in self.transaction_pool:
            if tx.subtype not in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                continue
            if tx.txto == address or tx.txfrom == address:
                logger.info('%s found in transaction pool', address)

                tmp_txn = {'subtype': tx.subtype,
                           'txhash': tx.txhash,
                           'block': 'unconfirmed',
                           'amount': tx.amount / 100000000.000000000,
                           'nonce': tx.nonce,
                           'ots_key': tx.ots_key,
                           'txto': tx.txto,
                           'txfrom': tx.txfrom,
                           'timestamp': 'unconfirmed'}

                if tx.subtype == transaction.TX_SUBTYPE_TX:
                    tmp_txn['fee'] = tx.fee / 100000000.000000000


                tmp_transactions.append(tmp_txn)
                txnhash_added.add(tx.txhash)

        addr['transactions'] = tmp_transactions

        my_txn = []
        try:
            my_txn = self.state.db.get('txn_' + address)
        except:
            pass

        for txn_hash in my_txn:
            txn_metadata = self.state.db.get(txn_hash)
            dict_txn_metadata = json.loads(txn_metadata[0])
            if dict_txn_metadata['subtype'] == transaction.TX_SUBTYPE_TX:
                tx = SimpleTransaction().json_to_transaction(txn_metadata[0])
            elif dict_txn_metadata['subtype'] == transaction.TX_SUBTYPE_COINBASE:
                tx = CoinBase().json_to_transaction(txn_metadata[0])

            if (tx.txto == address or tx.txfrom == address) and tx.txhash not in txnhash_added:
                logger.info('%s found in block %s', address, str(txn_metadata[1]))

                tmp_txn = {'subtype': tx.subtype,
                           'txhash': tx.txhash,
                           'block': txn_metadata[1],
                           'timestamp': txn_metadata[2],
                           'amount': tx.amount / 100000000.000000000,
                           'nonce': tx.nonce,
                           'ots_key': tx.ots_key,
                           'txto': tx.txto,
                           'txfrom': tx.txfrom}

                if tx.subtype == transaction.TX_SUBTYPE_TX:
                    tmp_txn['fee'] = tx.fee / 100000000.000000000

                addr['transactions'].append(tmp_txn)
                txnhash_added.add(tx.txhash)

        if len(addr['transactions']) > 0:
            addr['state']['transactions'] = len(addr['transactions'])

        if addr == {'transactions': {}}:
            addr = {'status': 'error', 'error': 'address not found', 'method': 'address', 'parameter': address}
        else:
            addr['status'] = 'ok'

        return json_print_telnet(addr)

    def last_unconfirmed_tx(self, n=1):
        addr = {'transactions': []}
        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': n}

        try:
            n = int(n)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        tx_num = len(self.transaction_pool)
        while tx_num > 0:
            tx_num -= 1
            tx = self.transaction_pool[tx_num]
            if tx.subtype != transaction.TX_SUBTYPE_TX:
                continue
            tmp_txn = {'txhash': tx.txhash,
                       'block': 'unconfirmed',
                       'timestamp': 'unconfirmed',
                       'amount': tx.amount / 100000000.000000000,
                       'type': tx.type}

            addr['transactions'].append(tmp_txn)

        addr['status'] = 'ok'
        return json_print_telnet(addr)

    # return json info on last n tx in the blockchain

    def last_tx(self, n=1):

        addr = {'transactions': []}
        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': n}

        try:
            n = int(n)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        try:
            last_txn = self.state.db.get('last_txn')
        except Exception:
            error['error'] = 'txnhash not found'
            return json_print_telnet(error)

        n = min(len(last_txn), n)
        while n > 0:
            n -= 1
            tx_meta = last_txn[n]
            tx = SimpleTransaction().json_to_transaction(tx_meta[0])
            tmp_txn = {'txhash': tx.txhash,
                       'block': tx_meta[1],
                       'timestamp': tx_meta[2],
                       'amount': tx.amount / 100000000.000000000,
                       'type': tx.subtype}

            addr['transactions'].append(tmp_txn)
            addr['status'] = 'ok'

        return json_print_telnet(addr)

    def richlist(self, n=None):
        """
        only feasible while chain is small..
        :param n:
        :return:
        """
        if not n:
            n = 5

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'richlist', 'parameter': n}

        try:
            n = int(n)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        if not self.state.state_uptodate(self.m_blockheight()):
            return json_print_telnet({'status': 'error', 'error': 'leveldb failed', 'method': 'richlist'})

        addr = self.state.db.return_all_addresses()
        richlist = sorted(addr, key=itemgetter(1), reverse=True)

        rl = {'richlist': {}}

        if len(richlist) < n:
            n = len(richlist)

        for rich in richlist[:n]:
            rl['richlist'][richlist.index(rich) + 1] = {}
            rl['richlist'][richlist.index(rich) + 1]['address'] = rich[0]
            rl['richlist'][richlist.index(rich) + 1]['balance'] = rich[1] / 100000000.000000000

        rl['status'] = 'ok'

        return json_print_telnet(rl)

    # return json info on last n blocks

    def last_block(self, n=1):

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_block', 'parameter': n}

        try:
            n = int(n)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        lb = []
        beginning = self.height() - n
        for blocknum in range(self.height(), beginning - 1, -1):
            block = self.m_get_block(blocknum)
            lb.append(block)

        last_blocks = {'blocks': []}
        i = 0
        for block in lb[1:]:
            i += 1
            tmp_block = {'blocknumber': block.blockheader.blocknumber,
                         'block_reward': block.blockheader.block_reward / 100000000.00000000,
                         'blockhash': block.blockheader.prev_blockheaderhash,
                         'timestamp': block.blockheader.timestamp,
                         'block_interval': lb[i - 1].blockheader.timestamp - block.blockheader.timestamp,
                         'number_transactions': len(block.transactions)}

            last_blocks['blocks'].append(tmp_block)

        last_blocks['status'] = 'ok'

        return json_print_telnet(last_blocks)

    # return json info on stake_commit list

    def stake_commits(self, data=None):

        sc = {'status': 'ok',
              'commits': {}}

        for c in self.stake_commit:
            # [stake_address, block_number, merkle_hash_tx, commit_hash]
            sc['commits'][str(c[1]) + '-' + c[3]] = {}
            sc['commits'][str(c[1]) + '-' + c[3]]['stake_address'] = c[0]
            sc['commits'][str(c[1]) + '-' + c[3]]['block_number'] = c[1]
            sc['commits'][str(c[1]) + '-' + c[3]]['merkle_hash_tx'] = c[2]
            sc['commits'][str(c[1]) + '-' + c[3]]['commit_hash'] = c[3]

        return json_print_telnet(sc)

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

        return json_print_telnet(stakers)

    def next_stakers(self, data=None):
        # (stake -> address, hash_term, nonce)
        next_stakers = {'status': 'ok',
                        'stake_list': []}

        for s in self.state.next_stake_list_get():
            tmp_stakers = {'address': s[0],
                           'balance': self.state.state_balance(s[0]) / 100000000.00000000,
                           'hash_terminator': s[1],
                           'nonce': s[2]}

            next_stakers['stake_list'].append(tmp_stakers)

        return json_print_telnet(next_stakers)

    @staticmethod
    def exp_win(data=None):
        # TODO: incomplete

        ew = {'status': 'ok',
              'expected_winner': {}}

        return json_print_telnet(ew)

    def stake_reveal_ones(self, data=None):

        sr = {'status': 'ok',
              'reveals': {}}

        for c in self.stake_reveal_one:
            sr['reveals'][str(c[1]) + '-' + str(c[2])] = {}
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['stake_address'] = c[0]
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['block_number'] = c[2]
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['headerhash'] = c[1]
            sr['reveals'][str(c[1]) + '-' + str(c[2])]['reveal'] = c[3]

        return json_print_telnet(sr)

    def ip_geotag(self, data=None):

        ip = {'status': 'ok',
              'ip_geotag': self.ip_list}

        x = 0
        for i in self.ip_list:
            ip['ip_geotag'][x] = i
            x += 1

        return json_print_telnet(ip)

    def stake_reveals(self, data=None):

        sr = {'status': 'ok',
              'reveals': {}}

        # chain.stake_reveal.append([stake_address, block_number, merkle_hash_tx, reveal])
        for c in self.stake_reveal:
            sr['reveals'][str(c[1]) + '-' + c[3]] = {}
            sr['reveals'][str(c[1]) + '-' + c[3]]['stake_address'] = c[0]
            sr['reveals'][str(c[1]) + '-' + c[3]]['block_number'] = c[1]
            sr['reveals'][str(c[1]) + '-' + c[3]]['merkle_hash_tx'] = c[2]
            sr['reveals'][str(c[1]) + '-' + c[3]]['reveal'] = c[3]

        return json_print_telnet(sr)

    def search(self, txcontains, islong=1):
        for tx in self.transaction_pool:
            if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
                logger.info('%s found in transaction pool..', txcontains)
                if islong == 1: json_print(tx)
        for block in self.m_blockchain:
            for tx in block.transactions:
                if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
                    logger.info('%s found in block %s', txcontains, str(block.blockheader.blocknumber))
                    if islong == 0: logger.info(('<tx:txhash> ' + tx.txhash))
                    if islong == 1: json_print(tx)
        return

    @staticmethod
    def get_chaindatafile(epoch):
        baseDir = os.path.join(config.user.data_path, config.dev.chain_file_directory)
        config.create_path(baseDir)
        return os.path.join(baseDir, 'chain.da' + str(epoch))

    def f_read_chain(self, epoch):
        delimiter = config.dev.binary_file_delimiter
        block_list = []
        if os.path.isfile(self.get_chaindatafile(epoch)) is False:
            if epoch != 0:
                return []
            logger.info('Creating new chain file')
            genesis_block = CreateGenesisBlock(self)
            block_list.append(genesis_block)
            return block_list

        try:
            with open(self.get_chaindatafile(epoch), 'rb') as myfile:
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
            if txn.subtype in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                self.state.db.put(txn.txhash,
                                  [txn.transaction_to_json(), block.blockheader.blocknumber,
                                   block.blockheader.timestamp])
                if txn.subtype == transaction.TX_SUBTYPE_TX:
                    self.update_wallet_tx_metadata(txn.txfrom, txn.txhash)
                self.update_wallet_tx_metadata(txn.txto, txn.txhash)
                self.update_txn_count(txn.txto, txn.txfrom)

    def f_write_m_blockchain(self):
        blocknumber = self.m_blockchain[-1].blockheader.blocknumber
        suffix = int(blocknumber // config.dev.blocks_per_chain_file)
        writeable = self.m_blockchain[-config.dev.disk_writes_after_x_blocks:]
        logger.info('Appending data to chain')

        with open(self.get_chaindatafile(suffix), 'ab') as myfile:
            for block in writeable:
                jsonBlock = json_bytestream(block)
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
            self.block_chain_buffer.add_block_mainchain(block,
                                                        verify_block_reveal_list=False,
                                                        validate=False)

        if len(self.m_blockchain) < config.dev.blocks_per_chain_file:
            return self.m_blockchain

        epoch = 1
        while os.path.isfile(self.get_chaindatafile(epoch)):
            del self.m_blockchain[:-1]
            chains = self.f_read_chain(epoch)

            for block in chains:
                self.block_chain_buffer.add_block_mainchain(block,
                                                            verify_block_reveal_list=False,
                                                            validate=False,
                                                            ignore_save_wallet=True)
            epoch += 1
        self.wallet.f_save_wallet()
        gc.collect()
        return self.m_blockchain

    def m_read_chain(self):
        if not self.m_blockchain:
            self.m_load_chain()
        return self.m_blockchain

    def load_from_file(self, blocknum):
        epoch = int(blocknum // config.dev.blocks_per_chain_file)
        with open(self.get_chaindatafile(epoch), 'rb') as f:
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
            return []

        beginning_blocknum = self.m_blockchain[0].blockheader.blocknumber
        diff = n - beginning_blocknum

        if diff < 0:
            return self.load_from_file(n)

        if diff < len(self.m_blockchain):
            return self.m_blockchain[diff]

        return []

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
        logger.info(('Blocksize, ', str(len(json_bytestream(b)))))
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