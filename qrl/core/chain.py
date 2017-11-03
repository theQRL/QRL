# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional

from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_TX, TX_SUBTYPE_DESTAKE
from collections import OrderedDict
from pyqrllib.pyqrllib import bin2hstr, XmssPool, str2bin
from qrl.core import config, logger
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Transaction import Transaction
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.wallet import Wallet
from qrl.core.block import Block
from qrl.core.helper import json_print
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256

import bz2
from time import time
import os
import copy
from collections import defaultdict
from decimal import Decimal

from qrl.crypto.xmss import XMSS


class Chain:
    def __init__(self, state):
        self.pstate = state                      # FIXME: Is this really a parameter?
        self.chain_dat_filename = os.path.join(config.user.data_path, config.dev.mnemonic_filename)

        self.wallet = Wallet()                  # FIXME: Why chain needs access to the wallet?
        self.staking_address = self.wallet.address_bundle[0].xmss.get_address().encode()

        self.blockchain = []                    # FIXME: Everyone is touching this
                                                # FIXME: Remove completely and trust the db memcache for this

        self.transaction_pool = []              # FIXME: Everyone is touching this
        self.prev_txpool = [None] * 1000        # TODO: use python dequeue
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = []
        self.duplicate_tx_pool = OrderedDict()  # FIXME: Everyone is touching this

        # OBSOLETE ????
        self.txhash_timestamp = []              # FIXME: Seems obsolete? Delete?

        # FIXME: Temporarily moving slave_xmss here
        self.slave_xmss = dict()
        self.slave_xmsspool = None
        self._init_slave_xmsspool(0)

    @property
    def height(self):
        # FIXME: This will probably get replaced by using rocksdb
        if len(self.blockchain):
            return self.blockchain[-1].blocknumber
        # FIXME: Height cannot be negative. In case this is used as index the code needs refactoring
        return -1

    ######## CHAIN RELATED

    def add_block(self, block: Block, validate=True)->bool:
        # TODO : minimum block validation in unsynced _state
        if block.blocknumber <= self.height():
            logger.warning("Block already in the chain")
            return False

        if block.blocknumber - 1 == self.height():
            if block.prev_headerhash != self.blockchain[-1].headerhash:
                logger.info('prev_headerhash of block doesnt match with headerhash of m_blockchain')
                return False
        elif block.blocknumber - 1 > 0:
            if block.blocknumber - 1 not in self.blocks or block.prev_headerhash != self.blocks[block.blocknumber - 1][0].block.headerhash:
                logger.info('No block found in buffer that matches with the prev_headerhash of received block')
                return False

        # FIXME: Combine all this with _add_block
        if validate:
            if not self._add_block(block):
                logger.info("Failed to add block by add_block, re-requesting the block #%s", block.blocknumber)
                return False
        else:
            if self.pstate.add_block(self, block, ignore_save_wallet=True) is True:
                self.blockchain.append(block)

        self.pstate.update_last_tx(block)
        self.pstate.update_tx_metadata(block)

        block_left = config.dev.blocks_per_epoch - (block.blocknumber - (block.epoch * config.dev.blocks_per_epoch))
        if block_left == 1:
            private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
            self._wallet_private_seeds[block.epoch + 1] = private_seed
            self.hash_chain[block.epoch + 1] = hashchain(private_seed, epoch=block.epoch + 1).hashchain

        self._clean_if_required(block.blocknumber)

        return True

    def _add_block(self, block: Block)->bool:
        if block.validate_block(buffered_chain=self):
            if self.pstate.add_block(self, block):
                self.blockchain.append(block)
                self.remove_tx_in_block_from_pool(block)
            else:
                logger.info('last block failed state/stake checks, removed from chain')
                self._validate_tx_pool()
                return False
        else:
            logger.info('add_block failed - block failed validation.')
            return False

        self.m_f_sync_chain()
        return True

    def create_block(self, reveal_hash, last_block_number=-1)->Optional[Block]:
        tmp_block = Block().create(self, reveal_hash, last_block_number)
        slave_xmss = self.get_slave_xmss(last_block_number + 1)

        if not slave_xmss:
            return None

        # FIXME: Why is it necessary to access the wallet here? Unexpected side effect
        self.wallet.save_slave(slave_xmss)

        return tmp_block

    def get_block(self, block_idx: int)->Optional[Block]:
        # Block chain has not been loaded yet?
        if len(self.blockchain) == 0:
            self.m_read_chain()

        if len(self.blockchain) > 0:
            # FIXME: The logic here is not very clear
            inmem_start_idx = self.blockchain[-1].blocknumber
            inmem_offset = block_idx - inmem_start_idx

            if inmem_offset < 0:
                return self._load_from_file(block_idx)

            if inmem_offset < len(self.blockchain):
                return self.blockchain[inmem_offset]

        return None

    def get_last_block(self)->Optional[Block]:
        if len(self.blockchain) == 0:
            return None
        return self.blockchain[-1]

    ######## TX POOL RELATED

    def add_tx_to_duplicate_pool(self, duplicate_txn):
        if len(self.duplicate_tx_pool) >= config.dev.transaction_pool_size:
            self.duplicate_tx_pool.popitem(last=False)

        self.duplicate_tx_pool[duplicate_txn.get_message_hash()] = duplicate_txn

    def update_pending_tx_pool(self, tx, peer):
        if len(self.pending_tx_pool) >= config.dev.transaction_pool_size:
            del self.pending_tx_pool[0]
            del self.pending_tx_pool_hash[0]
        self.pending_tx_pool.append([tx, peer])
        self.pending_tx_pool_hash.append(tx.txhash)

    def add_tx_to_pool(self, tx_class_obj):
        self.transaction_pool.append(tx_class_obj)
        self.txhash_timestamp.append(tx_class_obj.txhash)
        self.txhash_timestamp.append(time())

    def remove_tx_from_pool(self, tx_class_obj):
        self.transaction_pool.remove(tx_class_obj)
        self.txhash_timestamp.pop(self.txhash_timestamp.index(tx_class_obj.txhash) + 1)
        self.txhash_timestamp.remove(tx_class_obj.txhash)

    def remove_tx_in_block_from_pool(self, block_obj):
        for protobuf_tx in block_obj.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            for txn in self.transaction_pool:
                if tx.txhash == txn.txhash:
                    self.remove_tx_from_pool(txn)

    def _validate_tx_pool(self):
        result = True

        for tx in self.transaction_pool:
            if not tx.validate():
                result = False
                self.remove_tx_from_pool(tx)
                logger.info(('invalid tx: ', tx, 'removed from pool'))
                continue

            # FIXME: reference to a buffer
            tx_state = self.block_chain_buffer.get_stxn_state(blocknumber=self.block_chain_buffer.height() + 1,
                                                              addr=tx.txfrom)

            if not tx.validate_extended(tx_state=tx_state):
                result = False
                logger.warning('tx %s failed', tx.txhash)
                self.remove_tx_from_pool(tx)

        return result

    ####### CHAIN PERSISTANCE

    def m_read_chain(self):
        if not self.blockchain:
            self.m_load_chain()
        return self.blockchain

    def m_f_sync_chain(self):
        if (self.blockchain[-1].blocknumber + 1) % config.dev.disk_writes_after_x_blocks == 0:
            self._f_write_m_blockchain()
        return

    def _f_write_m_blockchain(self):
        blocknumber = self.blockchain[-1].blocknumber
        file_epoch = int(blocknumber // config.dev.blocks_per_chain_file)
        writeable = self.blockchain[-config.dev.disk_writes_after_x_blocks:]
        logger.debug('Writing chain to disk')

        with open(self._get_chain_datafile(file_epoch), 'ab') as myfile:
            for block in writeable:
                json_block = bytes(block.to_json(), 'utf-8')
                compressed_block = bz2.compress(json_block, config.dev.compression_level)
                block_pos = myfile.tell()
                block_size = len(compressed_block)

                self._update_block_metadata(block.blocknumber, block_pos, block_size)

                myfile.write(compressed_block)
                myfile.write(config.dev.binary_file_delimiter)

        del self.blockchain[:-1]

    def _load_from_file(self, blocknum):
        epoch = int(blocknum // config.dev.blocks_per_chain_file)

        block_offset, block_size = self._get_block_metadata(blocknum)

        with open(self._get_chain_datafile(epoch), 'rb') as f:
            f.seek(block_offset)
            json_block = bz2.decompress(f.read(block_size))

            block = Block.from_json(json_block)
            return block

    ####### MISC.. PROBABLY NEED TO REFACTOR

    @staticmethod
    def score(stake_address, reveal_one, balance=0, seed=None, verbose=False):
        if not seed:
            logger.info('Exception Raised due to seed none in score fn')
            raise Exception

        if not balance:
            logger.info(' balance 0 so score none ')
            logger.info(' stake_address %s', stake_address)
            return None
        reveal_seed = bin2hstr(sha256(str(reveal_one).encode() + str(seed).encode()))
        score = (Decimal(config.dev.N) - (Decimal(int(reveal_seed, 16)).log10() / Decimal(2).log10())) / Decimal(
            balance)

        if verbose:
            logger.info('=' * 10)
            logger.info('Score - %s', score)
            logger.info('reveal_one - %s', reveal_one)
            logger.info('seed - %s', seed)
            logger.info('balance - %s', balance)

        return score

    def _init_slave_xmsspool(self, starting_epoch):
        baseseed = self.wallet.address_bundle[0].xmss.get_seed()
        pool_size = 2
        self.slave_xmsspool = XmssPool(baseseed,
                                       config.dev.slave_xmss_height,
                                       starting_epoch,
                                       pool_size)

    def get_slave_xmss(self, blocknumber):
        epoch = self._get_mining_epoch(blocknumber)
        if epoch not in self.slave_xmss:
            if self.slave_xmsspool.getCurrentIndex() - epoch != 0:
                self._init_slave_xmsspool(epoch)
                return None
            if not self.slave_xmsspool.isAvailable():
                return None

            # Generate slave xmss
            assert (epoch == self.slave_xmsspool.getCurrentIndex())  # Verify we are not skipping trees
            tmp_xmss = self.slave_xmsspool.getNextTree()
            self.slave_xmss[epoch] = XMSS(tmp_xmss.getHeight(), _xmssfast=tmp_xmss)

            # TODO: Check why we are reading here
            data = self.wallet.read_slave()
            if data and data.address == self.slave_xmss[epoch].get_address():
                self.slave_xmss[epoch].set_index(data.index)

        return self.slave_xmss[epoch]

    def _get_mining_epoch(self, blocknumber):
        sv_list = self.block_chain_buffer.stake_list_get(blocknumber)

        epoch = blocknumber // config.dev.blocks_per_epoch

        if sv_list and self.staking_address in sv_list:
            activation_blocknumber = sv_list[self.staking_address].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch > blocknumber:
                epoch = activation_blocknumber // config.dev.blocks_per_epoch

        return epoch

    def hash_chain_get(self, blocknumber):
        epoch = self._get_mining_epoch(blocknumber)
        return self.block_chain_buffer.hash_chain[epoch]

    def select_hashchain(self, stake_address=None, hashchain=None, blocknumber=None):
        # NOTE: Users POS / Block

        if not hashchain:
            for s in self.block_chain_buffer.stake_list_get(blocknumber):
                if s[0] == stake_address:
                    hashchain = s[1]
                    break

        if not hashchain:
            return

        return hashchain

    # create a block from a list of supplied tx_hashes, check state to ensure validity..
    def create_stake_block(self, reveal_hash, last_block_number):
        # NOTE: Users POS

        t_pool2 = copy.deepcopy(self.transaction_pool)

        del self.transaction_pool[:]
        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        tx_nonce = defaultdict(int)
        total_txn = len(t_pool2)
        txnum = 0
        stake_validators_list = self.block_chain_buffer.get_stake_validators_list(last_block_number + 1)
        # FIX ME : Temporary fix, to include only either ST txn or TransferCoin txn for an address
        stake_txn = set()
        transfercoin_txn = set()
        destake_txn = set()
        while txnum < total_txn:
            tx = t_pool2[txnum]
            if self.block_chain_buffer.pubhashExists(tx.txfrom, tx.pubhash, last_block_number + 1):
                del t_pool2[txnum]
                total_txn -= 1
                continue

            if tx.subtype == TX_SUBTYPE_TX:
                if tx.txfrom in stake_txn:
                    logger.debug("Txn dropped: %s address is a Stake Validator", tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if tx.txfrom in stake_validators_list.sv_list and stake_validators_list.sv_list[tx.txfrom].is_active:
                    logger.debug("Txn dropped: %s address is a Stake Validator", tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if (tx.txfrom in stake_validators_list.future_stake_addresses and
                        stake_validators_list.future_stake_addresses[tx.txfrom].is_active):
                    logger.debug("Txn dropped: %s address is in Future Stake Validator", tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                transfercoin_txn.add(tx.txfrom)

            if tx.subtype == TX_SUBTYPE_STAKE:
                if tx.txfrom in transfercoin_txn:
                    logger.debug('Dropping st txn as transfer coin txn found in pool %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                # This check is to ignore multiple ST txn from same address
                if tx.txfrom in stake_txn:
                    logger.debug('Dropping st txn as existing Stake txn has been added %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.txfrom in destake_txn:
                    logger.debug('Dropping st txn as Destake txn has been added %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.txfrom in stake_validators_list.future_stake_addresses:
                    logger.debug('Skipping st as staker is already in future_stake_address')
                    logger.debug('Staker address : %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.txfrom in stake_validators_list.sv_list:
                    expiry = stake_validators_list.sv_list[tx.txfrom].activation_blocknumber + config.dev.blocks_per_epoch
                    if tx.activation_blocknumber < expiry:
                        logger.debug('Skipping st txn as it is already active for the given range %s', tx.txfrom)
                        del t_pool2[txnum]
                        total_txn -= 1
                        continue
                # skip 1st st txn without tx.first_hash in case its beyond allowed epoch blocknumber
                if tx.activation_blocknumber > self.block_chain_buffer.height() + config.dev.blocks_per_epoch + 1:
                    logger.debug('Skipping st as activation_blocknumber beyond limit')
                    logger.debug('Expected # less than : %s', (self.block_chain_buffer.height() + config.dev.blocks_per_epoch))
                    logger.debug('Found activation_blocknumber : %s', tx.activation_blocknumber)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                stake_txn.add(tx.txfrom)

            if tx.subtype == TX_SUBTYPE_DESTAKE:
                if tx.txfrom in stake_txn:
                    logger.debug('Dropping destake txn as stake txn has been added %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.txfrom in destake_txn:
                    logger.debug('Dropping destake txn as destake txn has already been added for %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.txfrom not in stake_validators_list.sv_list and tx.txfrom not in stake_validators_list.future_stake_addresses:
                    logger.debug('Dropping destake txn as %s not found in stake validator list', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                destake_txn.add(tx.txfrom)

            self.add_tx_to_pool(tx)
            tx_nonce[tx.txfrom] += 1
            tx._data.nonce = self.block_chain_buffer.get_stxn_state(last_block_number + 1, tx.txfrom)[0] + tx_nonce[tx.txfrom]
            txnum += 1

        # create the block..
        block_obj = self.create_block(reveal_hash, last_block_number)
        # reset the pool back
        self.transaction_pool = copy.deepcopy(t_pool2)

        return block_obj

    def search(self, query, islong=1):
        # FIXME: Refactor this. Prepare a look up
        for tx in self.transaction_pool:
            if tx.txhash == query or tx.txfrom == query or tx.txto == query:
                logger.info('%s found in transaction pool..', query)
                if islong == 1:
                    json_print(tx)

        for block in self.blockchain:
            for protobuf_tx in block.transactions:
                tx = Transaction.from_pbdata(protobuf_tx)
                if tx.txhash == query or tx.txfrom == query or tx.txto == query:
                    logger.info('%s found in block %s', query, str(block.blocknumber))
                    if islong == 0:
                        logger.info(('<tx:txhash> ' + tx.txhash))
                    if islong == 1:
                        json_print(tx)
