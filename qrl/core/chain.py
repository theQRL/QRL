# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE
from collections import OrderedDict, namedtuple
from pyqrllib.pyqrllib import getHashChainSeed, bin2hstr
from qrl.core import config, logger
from qrl.core.ChainBuffer import ChainBuffer
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.wallet import Wallet
from qrl.core.block import Block
from qrl.core.helper import json_bytestream, json_print
from qrl.core.Transaction import SimpleTransaction
from qrl.crypto.misc import sha256, merkle_tx_hash

import gc

import bz2
from io import StringIO
from time import time
from math import log, ceil
import heapq
import os, copy
import simplejson as json
from collections import defaultdict
from decimal import Decimal


BlockFrame = namedtuple('BlockFrame', 'position size')         # FIXME: Remove/Refactor. This is temporary

class Chain:
    def __init__(self, state):
        self.state = state
        self.wallet = Wallet()
        self.chain_dat_filename = os.path.join(config.user.data_path, config.dev.mnemonic_filename)

        # FIXME: should self.mining_address be self.staking_address
        self.mining_address = self.wallet.address_bundle[0].xmss.get_address()

        self.ping_list = []                     # FIXME: This has nothing to do with chain

        self.block_framedata = dict()

        self.transaction_pool = []
        self.txhash_timestamp = []
        self.m_blockchain = []
        self.blockheight_map = []
        self.block_chain_buffer = None  # Initialized by node.py
        self.prev_txpool = [None] * 1000        # TODO: use python dequeue
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = []
        self.duplicate_tx_pool = OrderedDict()

        self.stake_list = []
        self.stake_commit = []
        self.stake_reveal_one = []
        self.stake_ban_list = []
        self.stake_ban_block = {}
        self.stake_validator_latency = defaultdict(dict)

    def add_tx_to_duplicate_pool(self, duplicate_txn):
        if len(self.duplicate_tx_pool) >= config.dev.transaction_pool_size:
            self.duplicate_tx_pool.popitem(last=False)

        self.duplicate_tx_pool[duplicate_txn.get_message_hash()] = duplicate_txn

    def validate_reboot(self, mhash, nonce):
        # FIXME: Reboot validation in the chain? This is node related
        reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]
        try:
            # FIXME: Accessing DB directly
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
        # FIXME: Reboot validation in the chain? This is node related
        reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]

        try:
            # FIXME: Accessing DB directly
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
            target_chain += byte

        target_chain = (target_chain - 1) % (config.dev.hashchain_nums - 1)  # 1 Primary hashchain size

        return hashchain[-1], hashchain[target_chain]

    def select_winners(self, reveals, topN=1, blocknumber=None, block=None, seed=None):
        # FIXME: This is POS related
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

        reveal_one_number = int(bin2hstr(reveal_one), 16)
        score = (Decimal(config.dev.N) - (Decimal(reveal_one_number | seed).log10() / Decimal(2).log10())) / Decimal(
            balance)

        if verbose:
            logger.info('=' * 10)
            logger.info('Score - %s', score)
            logger.info('reveal_one - %s', reveal_one_number)
            logger.info('seed - %s', seed)
            logger.info('balance - %s', balance)

        return score

    def update_pending_tx_pool(self, tx, peer):
        if len(self.pending_tx_pool) >= config.dev.transaction_pool_size:
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
    def create_stake_block(self, reveal_hash, vote_hash, last_block_number):
        t_pool2 = copy.deepcopy(self.transaction_pool)

        del self.transaction_pool[:]
        curr_epoch = (last_block_number + 1) // config.dev.blocks_per_epoch
        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        tx_nonce = defaultdict(int)
        total_txn = len(t_pool2)
        txnum = 0
        while txnum < total_txn:
            tx = t_pool2[txnum]
            if self.block_chain_buffer.pubhashExists(tx.txfrom, tx.pubhash, last_block_number + 1):
                del t_pool2[txnum]
                total_txn -= 1
                continue
            if tx.subtype == TX_SUBTYPE_STAKE:
                epoch_blocknum = last_block_number + 1 - (curr_epoch * config.dev.blocks_per_epoch)

                # skip 1st st txn without tx.first_hash in case its beyond allowed epoch blocknumber
                if (not tx.first_hash) and epoch_blocknum >= config.dev.stake_before_x_blocks:
                    logger.warning('Skipping st as blocknumber beyond stake limit , CreateBlock()')
                    logger.warning('Expected ST txn before epoch_blocknumber : %s', config.dev.stake_before_x_blocks)
                    logger.warning('Found ST txn in epoch_blocknumber : %s', epoch_blocknum)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.epoch != curr_epoch:
                    logger.warning('Skipping st as epoch mismatch, CreateBlock()')
                    logger.warning('Expected st epoch : %s', curr_epoch)
                    logger.warning('Found st epoch : %s', tx.epoch)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                balance = 0
                next_sv_list = self.block_chain_buffer.next_stake_list_get(last_block_number + 1)
                if tx.txfrom in next_sv_list:
                    balance = next_sv_list[tx.txfrom].balance
                    threshold_blocknum = self.block_chain_buffer.get_threshold(last_block_number + 1, tx.txfrom)
                    if epoch_blocknum < threshold_blocknum - 1:
                        logger.warning('Skipping st as ST txn before threshold')
                        logger.warning('Expected : %s', threshold_blocknum - 1)
                        logger.warning('Found : %s', epoch_blocknum)
                        del t_pool2[txnum]
                        total_txn -= 1
                        continue
                # balance>0 only in case 1st st already accepted
                if not (balance > 0 or last_block_number == 0):
                    if tx.first_hash:
                        del t_pool2[txnum]
                        total_txn -= 1
                        continue
            self.add_tx_to_pool(tx)
            tx_nonce[tx.txfrom] += 1
            tx.nonce = self.block_chain_buffer.get_stxn_state(last_block_number + 1, tx.txfrom)[0] + tx_nonce[tx.txfrom]
            txnum += 1

        # create the block..
        block_obj = self.m_create_block(reveal_hash, vote_hash, last_block_number)
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
        prf = getHashChainSeed(seed, 1, 20000)

        # FIXME: Check with cyyber the purpose of this
        prf_range = []
        n_bits = int(ceil(log(n, 2)))
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

    def update_last_tx(self, block):
        if len(block.transactions) == 0:
            return
        last_txn = []

        try:
            # FIXME: Accessing DB directly
            last_txn = self.state.db.get('last_txn')
        except:
            pass

        for txn in block.transactions[-20:]:
            if txn.subtype == TX_SUBTYPE_TX:
                last_txn.insert(0,
                                [txn.transaction_to_json(), block.blockheader.blocknumber, block.blockheader.timestamp])
        del last_txn[20:]
        # FIXME: Accessing DB directly
        self.state.db.put('last_txn', last_txn)

    def update_wallet_tx_metadata(self, addr, new_txhash):
        try:
            # FIXME: Accessing DB directly
            txhash = self.state.db.get('txn_' + str(addr))
        except Exception:
            txhash = []
        txhash.append(bin2hstr(new_txhash))
        # FIXME: Accessing DB directly
        self.state.db.put('txn_' + str(addr), txhash)

    def update_txn_count(self, txto, txfrom):
        last_count = self.state.state_get_txn_count(txto)
        # FIXME: Accessing DB directly
        self.state.db.put('txn_count_' + str(txto), last_count + 1)
        last_count = self.state.state_get_txn_count(txfrom)
        # FIXME: Accessing DB directly
        self.state.db.put('txn_count_' + str(txfrom), last_count + 1)

    def update_tx_metadata(self, block):
        if len(block.transactions) == 0:
            return

        for txn in block.transactions:
            if txn.subtype in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
                # FIXME: Accessing DB directly
                self.state.db.put(bin2hstr(txn.txhash),
                                  [txn.transaction_to_json(), block.blockheader.blocknumber,
                                   block.blockheader.timestamp])
                if txn.subtype == TX_SUBTYPE_TX:
                    self.update_wallet_tx_metadata(txn.txfrom, txn.txhash)
                self.update_wallet_tx_metadata(txn.txto, txn.txhash)
                self.update_txn_count(txn.txto, txn.txfrom)

    def load_chain_by_epoch(self, epoch):

        chains = self.f_read_chain(epoch)
        self.m_blockchain.append(chains[0])

        self.state.state_read_genesis(self.m_get_block(0))
        self.block_chain_buffer = ChainBuffer(self)

        for block in chains[1:]:
            self.add_block_mainchain(block, validate=False)

        return self.m_blockchain

    def add_block_mainchain(self, block, validate=True):
        return self.block_chain_buffer.add_block_mainchain(chain=self,
                                                           block=block,
                                                           validate=validate)

    def m_read_chain(self):
        if not self.m_blockchain:
            self.m_load_chain()
        return self.m_blockchain

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

    def m_create_block(self, reveal_hash, vote_hash, last_block_number=-1):
        myBlock = Block()
        myBlock.create(self, reveal_hash, vote_hash, last_block_number)

        slave_xmss = self.block_chain_buffer.get_slave_xmss(last_block_number + 1)
        if not slave_xmss:
            return
        self.wallet.save_slave(slave_xmss)
        return myBlock

    def m_add_block(self, block_obj):
        if len(self.m_blockchain) == 0:
            self.m_read_chain()

        if block_obj.validate_block(chain=self) is True:
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
            if not block.validate_block(self):
                return False
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
        for tr in self.transaction_pool:
            if tr.validate_tx() is False:
                self.remove_tx_from_pool(tr)
                logger.info(('invalid tx: ', tr, 'removed from pool'))

        return True

    def create_my_tx(self, addr_from_idx, addr_to, amount, fee=0):
        # FIXME: The validation in the wallet should come here
        # FIXME: This method is not about the chain. It is about operations (should be on a higher level)

        if isinstance(addr_to, int):
            addr_to = self.wallet.address_bundle[addr_to].address

        xmss_from = self.wallet.address_bundle[addr_from_idx].xmss
        addr_from = xmss_from.get_address()
        block_number = self.block_chain_buffer.height() + 1

        tx_state = self.block_chain_buffer.get_stxn_state(block_number, addr_from)

        tx = SimpleTransaction().create(tx_state=tx_state,
                                        addr_to=addr_to,
                                        amount=amount,
                                        xmss=xmss_from,
                                        fee=fee)

        if tx and tx.state_validate_tx(tx_state=tx_state, transaction_pool=self.transaction_pool):
            self.add_tx_to_pool(tx)
            self.wallet.save_wallet()
            # need to keep state after tx ..use self.wallet.info to store index..
            # far faster than loading the 55mb self.wallet..
            return tx

        return False

    ############## BLOCK CHAIN PERSISTANCE

    @staticmethod
    def get_chaindatafile(epoch):
        baseDir = os.path.join(config.user.data_path, config.dev.chain_file_directory)
        config.create_path(baseDir)
        return os.path.join(baseDir, 'chain.da' + str(epoch))

    def m_load_chain(self):
        del self.m_blockchain[:]
        self.state.zero_all_addresses()

        self.load_chain_by_epoch(0)

        if len(self.m_blockchain) < config.dev.blocks_per_chain_file:
            return self.m_blockchain

        epoch = 1
        while os.path.isfile(self.get_chaindatafile(epoch)):
            del self.m_blockchain[:-1]
            chains = self.f_read_chain(epoch)

            for block in chains:
                self.add_block_mainchain(block, validate=False)

            epoch += 1
        self.wallet.save_wallet()

        gc.collect()
        return self.m_blockchain

    def f_write_m_blockchain(self):
        blocknumber = self.m_blockchain[-1].blockheader.blocknumber
        file_epoch = int(blocknumber // config.dev.blocks_per_chain_file)
        writeable = self.m_blockchain[-config.dev.disk_writes_after_x_blocks:]
        logger.info('Appending data to chain')

        with open(self.get_chaindatafile(file_epoch), 'ab') as myfile:
            for block in writeable:
                jsonBlock = bytes(json_bytestream(block), 'utf-8')
                compressedBlock = bz2.compress(jsonBlock, config.dev.compression_level)
                pos = myfile.tell()
                blockSize = len(compressedBlock)
                self.block_framedata[block.blockheader.blocknumber] = BlockFrame(pos, blockSize)
                myfile.write(compressedBlock)
                myfile.write(config.dev.binary_file_delimiter)

        del self.m_blockchain[:-1]
        gc.collect()

    def update_block_metadata(self, block_number, block_position, block_size):
        # FIXME: This is not scalable but it will fine fine for Oct2017 while we replace this with protobuf
        self.block_metadata[block_number] = [block_position, block_size]

    def get_block_metadata(self, block_number):
        # FIXME: This is not scalable but it will fine fine for Oct2017 while we replace this with protobuf
        return self.block_metadata[block_number]

    def load_from_file(self, blocknum):
        epoch = int(blocknum // config.dev.blocks_per_chain_file)

        pos, size = self.get_block_metadata(blocknum)

        with open(self.get_chaindatafile(epoch), 'rb') as f:
            framedata = self.block_framedata[blocknum]

            f.seek(framedata.position)
            jsonBlock = bz2.decompress(f.read(framedata.size))

            block = Block.from_json(jsonBlock)
            return block

    def f_read_chain(self, epoch):
        delimiter = config.dev.binary_file_delimiter

        block_list = []
        if not os.path.isfile(self.get_chaindatafile(epoch)):
            if epoch != 0:
                return []

            logger.info('Creating new chain file')
            genesis_block = GenesisBlock().set_chain(self)
            block_list.append(genesis_block)
            return block_list

        try:
            with open(self.get_chaindatafile(epoch), 'rb') as myfile:
                jsonBlock = bytearray()
                tmp = bytearray()
                count = 0
                offset = 0
                while True:
                    chars = myfile.read(config.dev.chain_read_buffer_size)
                    for char in chars:
                        offset += 1
                        if count > 0 and char != delimiter[count]:
                            count = 0
                            jsonBlock += tmp
                            tmp = bytearray()
                        if char == delimiter[count]:
                            tmp.append(delimiter[count])
                            count += 1
                            if count < len(delimiter):
                                continue
                            tmp = bytearray()
                            count = 0
                            pos = offset - len(delimiter) - len(jsonBlock)
                            jsonBlock = bz2.decompress(jsonBlock)

                            block = Block.from_json(jsonBlock)
                            self.block_framedata[block.blockheader.blocknumber] = BlockFrame(pos, len(jsonBlock))
                            block_list.append(block)

                            jsonBlock = bytearray()
                            continue
                        jsonBlock.append(char)
                    if len(chars) < config.dev.chain_read_buffer_size:
                        break
        except Exception as e:
            logger.error('IO error %s', e)
            return []

        return block_list
