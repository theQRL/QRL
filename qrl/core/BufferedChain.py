# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import defaultdict
from typing import Optional

import os
from pyqrllib.pyqrllib import str2bin, bin2hstr, XmssPool

from qrl.core import config, logger, Transaction
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.StateBuffer import StateBuffer
from qrl.core.BlockBuffer import BlockBuffer
from qrl.core.Transaction import CoinBase
from qrl.core.Transaction_subtypes import TX_SUBTYPE_TX, TX_SUBTYPE_DESTAKE, TX_SUBTYPE_STAKE, TX_SUBTYPE_COINBASE
from qrl.core.Block import Block
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256
import copy

from qrl.crypto.xmss import XMSS


class BufferedChain:
    def __init__(self, chain=None):
        self._chain = chain

        self.blocks = dict()                    # FIXME: Using a dict is very inefficient when index are a sequence
        self._pending_blocks = dict()

        self.epoch = max(0, self._chain.height()) // config.dev.blocks_per_epoch  # Main chain epoch
        self.epoch_seed = None

        private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
        self._wallet_private_seeds = {self.epoch: private_seed}
        self.hash_chain = dict()
        self.hash_chain[self.epoch] = hashchain(private_seed).hashchain

        if self._chain.height() > 0:
            self.epoch = self._chain.m_blockchain[-1].blocknumber // config.dev.blocks_per_epoch

        # FIXME: Temporarily moving slave_xmss here
        self.slave_xmss = dict()
        self.slave_xmsspool = None
        self._init_slave_xmsspool(0)

    @property
    def staking_address(self):
        return self._chain.staking_address

    @property
    def wallet(self):
        return self._chain.wallet

    @property
    def state(self):
        return self._chain.state

    @property
    def transaction_pool(self):
        return self._chain.tx_pool.transaction_pool

    @property
    def length(self):
        return len(self._chain.blockchain)

    def add_pending_block(self, block)->bool:
        # FIXME: only used by POS (pre_block_logic) . Make obsolete
        # TODO : minimum block validation in unsynced state
        block_idx = block.blocknumber
        self._pending_blocks[block_idx] = block
        return True

    def process_pending_blocks(self, block_expected_min: int):
        # FIXME: Pending blocks are not really used my. Why this?

        min_blocknum = min(self._pending_blocks.keys())
        max_blocknum = max(self._pending_blocks.keys())

        if len(self._pending_blocks) > 0 and min_blocknum == block_expected_min:
            # Below code is to stop downloading, once we see that we reached to blocknumber that are in pending_blocks
            # This could be exploited by sybil node, to send blocks in pending_blocks in order to disrupt downloading

            # FIXME: both min/max. Two passes
            logger.info('Processing pending blocks %s %s', min_blocknum, max_blocknum)

            # FIXME: avoid iterating by using keys
            for blocknum in range(min_blocknum, max_blocknum + 1):
                self.add_block(self._pending_blocks[blocknum])

            self._pending_blocks = dict()

            return True

        return False

    def get_last_block(self)->Optional[Block]:
        if len(self.blocks) == 0:
            return self._chain.get_last_block()

        # FIXME: Should this run max on the keys only? Or better keep track of the value..
        last_blocknum = max(self.blocks.keys())
        return self.blocks[last_blocknum][0].block      # FIXME: What does [0] refers to?

    def get_block(self, block_idx: int)->Optional[Block]:
        if block_idx in self.blocks:
            return self.blocks[block_idx][0].block      # FIXME: What does [0] refers to?
        return self._chain.get_block(block_idx)

    def add_block_mainchain(self, block, validate=True):
        if block.blocknumber <= self._chain.height():
            return

        if block.blocknumber - 1 == self._chain.height():
            if block.prev_headerhash != self._chain.m_blockchain[-1].headerhash:
                logger.info('prev_headerhash of block doesnt match with headerhash of m_blockchain')
                return
        elif block.blocknumber - 1 > 0:
            if block.blocknumber - 1 not in self.blocks or block.prev_headerhash != self.blocks[block.blocknumber - 1][0].block.headerhash:
                logger.info('No block found in buffer that matches with the prev_headerhash of received block')
                return

        if validate:
            if not self._chain.add_block(block):
                logger.info("Failed to add block by add_block, re-requesting the block #%s", block.blocknumber)
                return
        else:
            if self.height().add_block(self._chain, block, ignore_save_wallet=True) is True:
                self._chain.m_blockchain.append(block)

        block_left = config.dev.blocks_per_epoch - (
            block.blocknumber - (block.epoch * config.dev.blocks_per_epoch))

        if block_left == 1:
            private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
            self._wallet_private_seeds[block.epoch + 1] = private_seed
            self.hash_chain[block.epoch + 1] = hashchain(private_seed, epoch=block.epoch + 1).hashchain

        self._clean_if_required(block.blocknumber)

        self.epoch_seed = bin2hstr(sha256(tuple(block.reveal_hash) + str2bin(self.epoch_seed)))

        self.height().update_last_tx(block)
        self.height().update_tx_metadata(block)
        self.epoch = block.epoch
        return True

    def add_block(self, block: Block)->bool:
        if not block.validate_block(self):                        # This is here because of validators, etc
            logger.info('Block validation failed')
            logger.info('Block #%s', block.blocknumber)
            logger.info('Stake_selector %s', block.stake_selector)
            return False

        block_idx = block.blocknumber
        block_headerhash = block.headerhash
        block_prev_headerhash = block.prev_headerhash

        if block_idx <= self._chain.height():
            return False

        if block_idx - 1 == self._chain.height():
            if block_prev_headerhash != self._chain.m_blockchain[-1].headerhash:
                logger.warning('Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return False
        elif block_idx - 1 not in self.blocks or block_prev_headerhash != self.blocks[block_idx - 1][0].block.headerhash:
            logger.warning('Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
            return False

        if block_idx in self.blocks and block_headerhash == self.blocks[block_idx][0].block.headerhash:
            return False

        if (block_idx - config.dev.reorg_limit) in self.blocks:
            self._move_to_mainchain(block_idx - config.dev.reorg_limit)

        stake_reward = {}

        state_buffer = StateBuffer()

        if block_idx - 1 == self._chain.height():
            stake_validators_list = copy.deepcopy(self.height().stake_validators_list)
            stxn_state = dict()
            # TODO: Optimization required
            if not self._state_add_block_buffer(block, stake_validators_list, stxn_state):
                logger.warning('State_validate_block failed inside chainbuffer #%d', block.blocknumber)
                return False

            block_buffer = BlockBuffer(block, stake_reward, self._chain, self.epoch_seed,
                                       self._get_st_balance(block.transactions[0].addr_from,
                                                            block.blocknumber))

            state_buffer.set_next_seed(block.reveal_hash, self.epoch_seed)
            state_buffer.stake_validators_list = stake_validators_list
            state_buffer.stxn_state = stxn_state
            state_buffer.update_stxn_state(self.height())
        else:
            block_state_buffer = self.blocks[block_idx - 1]
            parent_state_buffer = block_state_buffer[1]
            parent_seed = block_state_buffer[1].next_seed

            stake_validators_list = copy.deepcopy(parent_state_buffer.stake_validators_list)
            stxn_state = copy.deepcopy(parent_state_buffer.stxn_state)
            if not self._state_add_block_buffer(block, stake_validators_list, stxn_state):
                logger.warning('State_validate_block failed inside chainbuffer #%s', block.blocknumber)
                return False
            block_buffer = BlockBuffer(block, stake_reward, self._chain, parent_seed,
                                       self._get_st_balance(block.transactions[0].addr_from,
                                                            block.blocknumber))
            state_buffer.stake_validators_list = stake_validators_list
            state_buffer.stxn_state = stxn_state
            state_buffer.update(self.height(), parent_state_buffer, block)

        if block_idx not in self.blocks:
            self.blocks[block_idx] = [block_buffer, state_buffer]
        else:
            old_block_buffer = self.blocks[block_idx][0]

            if block_buffer.score < old_block_buffer.score:
                self.blocks[block_idx] = [block_buffer, state_buffer]
                if block_idx + 1 in self.blocks:
                    self._remove_block(block_idx + 1)
            elif block_buffer.score == old_block_buffer.score:  # When two blocks having equal score
                oldheaderhash = old_block_buffer.block.headerhash
                newheaderhash = block_buffer.block.headerhash
                if int(bin2hstr(newheaderhash), 16) < int(bin2hstr(oldheaderhash), 16):
                    self.blocks[block_idx] = [block_buffer, state_buffer]
                    if block_idx + 1 in self.blocks:
                        self._remove_block(block_idx + 1)

        return True

    def _remove_block(self, blocknumber):
        if blocknumber not in self.blocks:
            return

        while blocknumber in self.blocks:
            del self.blocks[blocknumber]
            blocknumber += 1

    def _state_add_block_buffer(self, block, stake_validators_list, address_txn):
        # FIXME: This is mixing states
        self._chain.pstate.load_address_state(self._chain, block, address_txn)
        is_success = self._chain.pstate.update(block, stake_validators_list, address_txn)
        if is_success:
            self._commit(block, stake_validators_list)
            logger.info('[ChainBuffer] Block #%s added  stake: %s', block.blocknumber,
                        block.stake_selector)
        return is_success

    def create_block(self, reveal_hash, last_block_number=-1) -> Optional[Block]:
        # FIXME: This can probably happen inside get_block, why two methods?
        if last_block_number == -1:
            last_block = self.get_last_block()
        else:
            last_block = self.get_block(last_block_number)
        # FIXME

        signing_xmss = self.get_slave_xmss(last_block.block_number + 1)

        sv_list = self.get_stake_validators_list(last_block.block_number + 1).sv_list
        nonce = sv_list[self._chain.pstate].nonce + 1

        new_block = Block.create(staking_address=self.staking_address,
                                 block_number=last_block.block_number + 1,
                                 reveal_hash=reveal_hash,
                                 prevblock_headerhash=last_block.headerhash,
                                 transactions=self._chain.tx_pool.transaction_pool,
                                 duplicate_transactions=self._chain.tx_pool.duplicate_tx_pool,
                                 signing_xmss=signing_xmss,
                                 nonce=nonce)

        slave_xmss = self.get_slave_xmss(last_block.block_number + 1)

        if not slave_xmss:
            return None     # FIXME: Not clear why the skip and return False

        # FIXME: Why is it necessary to access the wallet here? Unexpected side effect?
        self.wallet.save_slave(slave_xmss)

        return new_block

    def validate_block(self, buffered_chain):  # check validity of new block..
        # FIXME: This is accessing buffered chain. It does not belong here

        try:
            # FIXME: review this.. Too complicated

            blk_header = self.blockheader
            last_blocknum = blk_header.blocknumber - 1
            last_block = buffered_chain.get_block(last_blocknum)

            if not self.blockheader.validate(last_block.blockheader):
                return False

            if len(self.transactions) == 0:
                logger.warning('BLOCK : There must be atleast 1 txn')
                return False

            # Validate coinbase
            # FIXME: Check if it is possible to delegate validation to coinbase transaction. Why the code is in Block?
            coinbase_tx = CoinBase(self.transactions[0])

            if coinbase_tx.subtype != TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False

            if coinbase_tx.txto != self.blockheader.stake_selector:
                logger.info('Non matching txto and stake_selector')
                logger.info('txto: %s stake_selector %s', coinbase_tx.txfrom, self.blockheader.stake_selector)
                return False

            if coinbase_tx.amount != self.blockheader.block_reward + self.blockheader.fee_reward:
                logger.info('Block_reward doesnt match')
                logger.info('Found: %s', coinbase_tx.amount)
                logger.info('Expected: %s', self.blockheader.block_reward + self.blockheader.fee_reward)
                logger.info('block_reward: %s', self.blockheader.block_reward)
                logger.info('fee_reward: %s', self.blockheader.fee_reward)
                return False

            if blk_header.blocknumber == 1:
                found = False
                for protobuf_tx in self.transactions:
                    tx = Transaction.from_pbdata(protobuf_tx)
                    if tx.subtype == TX_SUBTYPE_STAKE:
                        if tx.txfrom == blk_header.stake_selector:
                            found = True
                            reveal_hash = buffered_chain.chain.select_hashchain(coinbase_tx.txto, tx.hash,
                                                                                blocknumber=1)
                            if sha256(bin2hstr(tuple(blk_header.reveal_hash)).encode()) != reveal_hash:
                                logger.warning('reveal_hash does not hash correctly to terminator: failed validation')
                                return False

                if not found:
                    logger.warning('Stake selector not in block.stake: failed validation')
                    return False

            else:  # we look in stake_list for the hash terminator and hash to it..
                stake_validators_list = buffered_chain.get_stake_validators_list(self.blockheader.blocknumber)
                if coinbase_tx.txto not in stake_validators_list.sv_list:
                    logger.warning('Stake selector not in stake_list for this epoch..')
                    return False

                if not stake_validators_list.validate_hash(blk_header.reveal_hash,
                                                           blk_header.blocknumber,
                                                           coinbase_tx.txto):
                    logger.warning('Supplied hash does not iterate to terminator: failed validation')
                    return False

            if not self._validate_tx_in_block(buffered_chain):
                logger.warning('Block validate_tx_in_block error: failed validation')
                return False

        except Exception as e:
            logger.exception(e)
            return False

        return True

    def _validate_tx_in_block(self, buffered_chain):
        # FIXME: This is accessing buffered chain. It does not belong here
        # Validating coinbase txn

        # FIXME: Again checking coinbase here?
        coinbase_txn = CoinBase(self.transactions[0])

        sv_list = buffered_chain.stake_list_get(self.blockheader.blocknumber)
        valid = coinbase_txn.validate_extended(sv_list=sv_list, blockheader=self.blockheader)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_num in range(1, len(self.transactions)):
            protobuf_tx = self.transactions[tx_num]
            tx = Transaction.from_pbdata(protobuf_tx)
            if not tx.validate():
                logger.warning('invalid tx in block')
                return False

        for protobuf_tx in self.duplicate_transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if not tx.validate():
                logger.warning('invalid duplicate tx in block')
                return False

        return True

    #############################################3
    #############################################3
    #############################################3
    #############################################3

    def _update_hash_chain(self, blocknumber):
        epoch = int((blocknumber + 1) // config.dev.blocks_per_epoch)
        logger.info('Created new hash chain')

        prev_private_seed = self._wallet_private_seeds[epoch - 1]
        self._wallet_private_seeds[epoch] = prev_private_seed
        self.hash_chain[epoch] = hashchain(prev_private_seed, epoch=epoch).hashchain

    def _commit(self, block, stake_validators_list):
        blocknumber = block.blocknumber
        blocks_left = get_blocks_left(blocknumber)
        stake_validators_list.sv_list[block.stake_selector].nonce += 1
        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in stake_validators_list.sv_list:
                stake_validators_list.sv_list[dup_tx.coinbase1.txto].is_banned = True

        if blocks_left == 1:
            self._update_hash_chain(blocknumber)

        stake_validators_list.update_sv(blocknumber)

    def _get_epoch_seed(self, blocknumber):
        try:
            if blocknumber - 1 == self._chain.height():
                return int(str(self.epoch_seed), 16)

            return int(str(self.blocks[blocknumber - 1][1].next_seed), 16)
        except KeyError:
            self.error_msg('get_epoch_seed', blocknumber)
        except Exception as e:
            self.error_msg('get_epoch_seed', blocknumber, e)

        return None

    def _move_to_mainchain(self, blocknum):
        block = self.blocks[blocknum][0].block
        if not self.height().add_block(self._chain, block):
            logger.info('last block failed state/stake checks, removed from chain')
            return False

        self._chain.m_blockchain.append(block)
        self._chain.remove_tx_in_block_from_pool(block)  # modify fn to keep transaction in memory till reorg
        self._chain.m_f_sync_chain()

        self.epoch_seed = self.blocks[blocknum][1].next_seed

        self.epoch = int(blocknum // config.dev.blocks_per_epoch)

        self._clean_if_required(blocknum)

        del (self.blocks[blocknum])

        self.height().update_last_tx(block)
        self.height().update_tx_metadata(block)
        return True

    def height(self):
        if len(self.blocks) == 0:
            return self._chain.height()
        return max(self.blocks.keys())             # FIXME: max over a dictionary?

    def pubhashExists(self, addr, pubhash, blocknumber):
        # FIXME: Move to chain
        state_addr = self.get_stxn_state(blocknumber, addr)

        if state_addr is None:
            logger.info('-->> state_addr None not possible')
            return False

        if pubhash in state_addr[2]:
            return True

        return False

    ###########################
    ###########################
    ###########################
    ###########################

    def get_block_n_score(self, blocknumber):
        try:
            return self.blocks[blocknumber][0].score
        except KeyError:
            logger.error('get_block_n_score, blocknumber not in self.blocks #%s', blocknumber)
        except Exception as e:
            logger.error('Unexpected Exception')
            logger.error('%s', e)

    def _get_last_blocknumber_timestamp(self):
        last_block = self.get_last_block()
        return last_block.blocknumber, last_block.timestamp

    def bkmr_tracking_blocknumber(self, ntp):
        blocknumber, timestamp = self._get_last_blocknumber_timestamp()
        if ntp.getTime() - timestamp >= config.dev.minimum_minting_delay - config.dev.timestamp_error:
            return blocknumber + 1
        return blocknumber

    def verify_BK_hash(self, data, conn_identity):
        blocknum = data.block_number
        stake_selector = data.stake_selector

        prev_headerhash = data.prev_headerhash

        if blocknum <= self._chain.height():
            return False

        sv_list = self.stake_list_get(blocknum)

        if not sv_list:
            return

        if stake_selector not in sv_list:
            return

        if sv_list[stake_selector].is_banned:
            logger.warning('Rejecting block created by banned stake selector %s', stake_selector)
            return

        if not sv_list[stake_selector].is_active:
            logger.warning('Rejecting block created by inactive stake selector %s', stake_selector)
            return

        if blocknum - 1 == self._chain.height():
            if prev_headerhash != self._chain.m_blockchain[-1].headerhash:
                logger.warning('verify_BK_hash Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return
            return True
        elif blocknum - 1 not in self.blocks or prev_headerhash != self.blocks[blocknum - 1][0].block.headerhash:
            logger.warning('verify_BK_hash Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
            return

        reveal_hash = data.reveal_hash

        stake_validators_list = self.get_stake_validators_list(blocknum)

        if not stake_validators_list.validate_hash(reveal_hash,
                                                   blocknum,
                                                   stake_address=stake_selector):
            logger.info('%s reveal doesnt hash to stake terminator reveal %s',
                        conn_identity, reveal_hash)
            return

        score = self.score_BK_hash(data)
        return self._is_better_block(blocknum, score)

    def score_BK_hash(self, data):
        blocknum = data.block_number
        stake_selector = data.stake_selector

        reveal_hash = tuple(data.reveal_hash)

        seed = self._chain.block_chain_buffer._get_epoch_seed(blocknum)
        score = self._chain.score(stake_address=stake_selector,
                                  reveal_one=reveal_hash,
                                  balance=self._get_st_balance(stake_selector, blocknum),
                                  seed=seed)

        return score

    def _is_better_block(self, blocknum, score):
        if blocknum not in self.blocks:
            return True

        oldscore = self.blocks[blocknum][0].score

        if score < oldscore:
            return True

        return False

    def is_duplicate_block(self, blocknum, prev_blockheaderhash, stake_selector):
        """
        A block is considered as a dirty block, if same stake validator created two different blocks
        for the same blocknumber having same prev_blockheaderhash.
        """
        if blocknum > self.height():
            return

        best_block = self.get_block(blocknum)

        if best_block.prev_headerhash != prev_blockheaderhash:
            return

        if best_block.stake_selector != stake_selector:
            return

        return True

    def _get_st_balance(self, stake_address, blocknumber):
        if stake_address is None:
            logger.error('stake address should not be none, returning None')
            return None

        try:
            if blocknumber - 1 == self._chain.height():
                if stake_address in self.height().stake_validators_list.sv_list:
                    return self.height().stake_validators_list.sv_list[stake_address].balance
                logger.info('Blocknumber not found')
                return None

            return self.blocks[blocknumber - 1][1].stake_validators_list.sv_list[stake_address].balance
        except KeyError:
            self.error_msg('get_st_balance', blocknumber)
        except Exception as e:
            self.error_msg('get_st_balance', blocknumber, e)

        return None

    def get_stxn_state(self, blocknumber, addr):
        try:
            if blocknumber - 1 == self._chain.height() or addr not in self.blocks[blocknumber - 1][1].stxn_state:
                tmp_state = self.height().get_address(addr)
                return tmp_state

            stateBuffer = self.blocks[blocknumber - 1][1]

            if addr in stateBuffer.stxn_state:
                return copy.deepcopy(stateBuffer.stxn_state[addr])  # FIXME: Why deepcopy?

            return self.height().get_address(addr)
        except KeyError:
            self.error_msg('get_stxn_state', blocknumber)
        except Exception as e:
            self.error_msg('get_stxn_state', blocknumber, e)

        return None

    def stake_list_get(self, blocknumber):
        try:
            if blocknumber - 1 > self.height():
                return None

            if blocknumber - 1 == self._chain.height():
                return self.height().stake_validators_list.sv_list

            stateBuffer = self.blocks[blocknumber - 1][1]

            return stateBuffer.stake_validators_list.sv_list
        except KeyError:
            self.error_msg('stake_list_get', blocknumber)
        except Exception as e:
            self.error_msg('stake_list_get', blocknumber, e)

        return None

    def future_stake_addresses(self, blocknumber):
        try:
            if blocknumber - 1 == self._chain.height():
                return self.height().stake_validators_list.future_stake_addresses

            stateBuffer = self.blocks[blocknumber - 1][1]

            return stateBuffer.stake_validators_list.future_stake_addresses
        except KeyError:
            self.error_msg('stake_list_get', blocknumber)
        except Exception as e:
            self.error_msg('stake_list_get', blocknumber, e)

        return None

    def get_stake_validators_list(self, blocknumber):
        try:
            if blocknumber - 1 == self._chain.height():
                return self.height().stake_validators_list

            return self.blocks[blocknumber - 1][1].stake_validators_list
        except KeyError:
            self.error_msg('get_stake_validators_list', blocknumber)
        except Exception as e:
            self.error_msg('get_stake_validators_list', blocknumber, e)

        return None

    def _clean_mining_data(self, blocknumber):
        """
        Removes the mining data from the memory.
        :param blocknumber:
        :return:
        """

        prev_epoch = blocknumber // config.dev.blocks_per_epoch

        if prev_epoch in self._wallet_private_seeds:
            del self._wallet_private_seeds[prev_epoch]

        if prev_epoch in self.hash_chain:
            del self.hash_chain[prev_epoch]

        # FIXME: This should not be here
        if prev_epoch in self._chain.slave_xmss:
            del self._chain.slave_xmss[prev_epoch]

    def _clean_if_required(self, blocknumber):
        """
        Checks if the mining data such as private_seeds, hash_chain, slave_xmss
        are no more required.
        :param blocknumber:
        :return:
        """
        prev_epoch = int((blocknumber - 1) // config.dev.blocks_per_epoch)

        sv_list = self.height().stake_validators_list.sv_list
        if self.height() in sv_list:
            activation_blocknumber = sv_list[self.height()].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch == blocknumber:
                self._clean_mining_data(blocknumber - 1)
        elif prev_epoch != self.epoch:
            self._clean_mining_data(blocknumber - 1)


    ###########################
    ###########################
    ###########################
    ###########################

    def error_msg(self, func_name, blocknum, exception=None):
        if exception:
            logger.error(func_name + ' Unknown exception at blocknum: %s', blocknum)
            logger.exception(exception)
            return

        logger.error('%s blocknum not found in blocks %s', func_name, blocknum)
        if self.blocks:
            logger.error('Min block num %s', min(self.blocks))
            logger.error('Max block num %s', max(self.blocks))

    ###########################
    ###########################
    ###########################
    ###########################

    # TODO: Persistence will move to rocksdb

    def read_genesis(self):
        logger.info('genesis:')

        genesis_info = GenesisBlock.load_genesis_info()
        for address in genesis_info:
            self._chain.pstate._save_address_state(address, [0, genesis_info[address], []])

        return True

    def load(self):
        # TODO: Persistence will move to rocksdb
        self._chain.blockchain = []

        # FIXME: Adds an empty block, later ignores and overwrites.. A complete genesis block should be here
        genesis_block = GenesisBlock().set_staking_address(self.staking_address)
        self._chain.pstate.zero_all_addresses()
        self.read_genesis()

        # FIXME: Direct access - Breaks encapsulation
        self._chain.blockchain.append(genesis_block)                       # FIXME: Adds without checking???

        # FIXME: it is not nice how genesis block is ignored
        tmp_chain = self._chain._f_read_chain(0)
        if len(tmp_chain) > 0:
            for block in tmp_chain[1:]:
                self.add_block_mainchain(block, validate=False)

        epoch = 1
        # FIXME: Avoid checking files here..
        while os.path.isfile(self._chain._get_chain_datafile(epoch)):
            del self._chain.blockchain[:-1]                                # FIXME: This optimization could be encapsulated
            for block in self._chain._f_read_chain(epoch):
                self.add_block_mainchain(block, validate=False)

            epoch += 1

        self.wallet.save_wallet()
        return self._chain.blockchain

    ###########################
    ###########################
    ###########################
    ###########################

    # create a block from a list of supplied tx_hashes, check state to ensure validity..
    def create_stake_block(self, reveal_hash, last_block_number):
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        t_pool2 = copy.deepcopy(self.transaction_pool)

        del self.transaction_pool[:]
        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        tx_nonce = defaultdict(int)
        total_txn = len(t_pool2)
        txnum = 0
        stake_validators_list = self.get_stake_validators_list(last_block_number + 1)
        # FIX ME : Temporary fix, to include only either ST txn or TransferCoin txn for an address
        stake_txn = set()
        transfercoin_txn = set()
        destake_txn = set()
        while txnum < total_txn:
            tx = t_pool2[txnum]
            if self.pubhashExists(tx.txfrom, tx.pubhash, last_block_number + 1):
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
                if tx.activation_blocknumber > self.height() + config.dev.blocks_per_epoch + 1:
                    logger.debug('Skipping st as activation_blocknumber beyond limit')
                    logger.debug('Expected # less than : %s', (self.height() + config.dev.blocks_per_epoch))
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

            self._chain.tx_pool.add_tx_to_pool(tx)
            tx_nonce[tx.txfrom] += 1
            tx._data.nonce = self.get_stxn_state(last_block_number + 1, tx.txfrom)[0] + tx_nonce[tx.txfrom]
            txnum += 1

        # create the block..
        block_obj = self._chain.create_block(reveal_hash, last_block_number)

        # reset the pool back
        # FIXME: Reset pool from here?
        self._chain.tx_pool.transaction_pool = copy.deepcopy(t_pool2)

        return block_obj

    def hash_chain_get(self, blocknumber):
        epoch = self._get_mining_epoch(blocknumber)
        return self.hash_chain[epoch]

    def select_hashchain(self, stake_address=None, hashchain=None, blocknumber=None):
        # NOTE: Users POS / Block

        if not hashchain:
            for s in self.stake_list_get(blocknumber):
                if s[0] == stake_address:
                    hashchain = s[1]
                    break

        if not hashchain:
            return

        return hashchain

    def _get_mining_epoch(self, blocknumber):
        sv_list = self.stake_list_get(blocknumber)

        epoch = blocknumber // config.dev.blocks_per_epoch

        if sv_list and self.staking_address in sv_list:
            activation_blocknumber = sv_list[self.staking_address].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch > blocknumber:
                epoch = activation_blocknumber // config.dev.blocks_per_epoch

        return epoch

    ###################################
    ###################################
    ###################################
    ###################################

    def search(self, query):
        # FIXME: Refactor this. Prepare a look up in the DB
        for tx in self._chain.tx_pool.transaction_pool:
            if tx.txhash == query or tx.txfrom == query or tx.txto == query:
                logger.info('%s found in transaction pool..', query)
                return tx

        return self._chain.search(query)

    ###################################
    ###################################
    ###################################
    ###################################

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
