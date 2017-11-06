# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import defaultdict
from typing import Optional

import os
from pyqrllib.pyqrllib import str2bin, bin2hstr, XmssPool

from qrl.core import config, logger, Wallet
from qrl.core.Chain import Chain
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.StateBuffer import StateBuffer
from qrl.core.BlockBuffer import BlockBuffer
from qrl.core.Transaction import CoinBase, Transaction
from qrl.core.TransactionPool import TransactionPool
from qrl.core.Transaction_subtypes import *
from qrl.core.Block import Block
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256
import copy

from qrl.crypto.xmss import XMSS


# TODO: Rename to unstable/fluid chain or something similar?
class BufferedChain:
    def __init__(self, chain: Chain):
        self._chain = chain

        self.blocks = dict()                    # FIXME: Using a dict is very inefficient when index are a sequence

        self._pending_blocks = dict()

        self.epoch = max(0, self._chain.height()) // config.dev.blocks_per_epoch  # Main chain epoch
        self.epoch_seed = None
        if self._chain.height() > 0:
            self.epoch = self._chain.blockchain[-1].block_number // config.dev.blocks_per_epoch

        private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
        self._wallet_private_seeds = {self.epoch: private_seed}
        self.hash_chain = dict()
        self.hash_chain[self.epoch] = hashchain(private_seed).hashchain

        self.tx_pool = TransactionPool()  # FIXME: This is not stable, it should not be in chain

        self.stake_list = []

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
        return self.tx_pool.transaction_pool

    @property
    def length(self):
        return len(self._chain.blockchain)

    @property
    def height(self)->int:
        if len(self.blocks) == 0:
            return self._chain.height()
        return max(self.blocks.keys())             # FIXME: max over a dictionary?

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    # Block handling

    def add_pending_block(self, block)->bool:
        # FIXME: only used by POS (pre_block_logic) . Make obsolete
        # TODO : minimum block validation in unsynced state
        block_idx = block.block_number
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

    def add_block_mainchain(self, block, validate=True)->bool:
        if block.block_number <= self._chain.height():
            return False

        # FIXME: Avoid +1/-1, assign a them to make things clear
        if block.block_number - 1 == self._chain.height():
            if block.prev_headerhash != self._chain.blockchain[-1].headerhash:
                logger.info('prev_headerhash of block doesnt match with headerhash of blockchain')
                return False
        elif block.block_number - 1 > 0:
            if block.block_number - 1 not in self.blocks or block.prev_headerhash != self.blocks[block.block_number - 1][0].block.headerhash:
                logger.info('No block found in buffer that matches with the prev_headerhash of received block')
                return False

        # FIXME: Reorganize/rewrite this after refactoring is stable. Crazy nesting
        if validate:
            if self.validate_block(block):
                if self._chain.add_block(block):

                    self.tx_pool.remove_tx_in_block_from_pool(block)

                    # FIXME: clean this up
                    block_left = config.dev.blocks_per_epoch
                    block_left -= block.block_number - (block.epoch * config.dev.blocks_per_epoch)

                    if block_left == 1:
                        private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
                        self._wallet_private_seeds[block.epoch + 1] = private_seed
                        self.hash_chain[block.epoch + 1] = hashchain(private_seed, epoch=block.epoch + 1).hashchain

                    self._clean_if_required(block.block_number)
                else:
                    logger.info("Failed to add block by add_block, "
                                "re-requesting the block #%s", block.block_number)
                    self._validate_tx_pool()
                    return False
            else:
                logger.info('add_block failed - block failed validation.')
                return False
        else:
            if self.add_block(block, ignore_save_wallet=True):
                self._chain.blockchain.append(block)

        block_left = config.dev.blocks_per_epoch - (block.block_number - (block.epoch * config.dev.blocks_per_epoch))

        if block_left == 1:
            private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
            self._wallet_private_seeds[block.epoch + 1] = private_seed
            self.hash_chain[block.epoch + 1] = hashchain(private_seed, epoch=block.epoch + 1).hashchain

        self._clean_if_required(block.block_number)

        self.epoch_seed = bin2hstr(sha256(tuple(block.reveal_hash) + str2bin(self.epoch_seed)))

        self._chain.pstate.update_last_tx(block)
        self._chain.pstate.update_tx_metadata(block)
        self.epoch = block.epoch
        return True

    def _validate_tx_pool(self):
        result = True

        # FIXME: Breaks encapsulation
        for tx in self.tx_pool.transaction_pool:
            if not tx.validate():
                result = False
                self.tx_pool.remove_tx_from_pool(tx)
                logger.info(('invalid tx: ', tx, 'removed from pool'))
                continue

            # FIXME: reference to a buffer
            tx_state = self.get_stxn_state(blocknumber=self.height + 1, addr=tx.txfrom)

            if not tx.validate_extended(tx_state=tx_state):
                result = False
                logger.warning('tx %s failed', tx.txhash)
                self.tx_pool.remove_tx_from_pool(tx)

        return result

    def add_block(self, block: Block)->bool:
        if not self.validate_block(block):                        # This is here because of validators, etc
            logger.info('Block validation failed')
            logger.info('Block #%s', block.block_number)
            logger.info('Stake_selector %s', block.stake_selector)
            return False

        block_headerhash = block.headerhash
        block_prev_headerhash = block.prev_headerhash

        if block.block_number <= self._chain.height():
            return False

        # FIXME: This is extremely complicated. Review/refactor

        # FIXME: Avoid +1/-1, assign a them to make things clear
        # FIXME: Avoid +1/-1, assign a them to make things clear
        if block.block_number - 1 == self._chain.height():
            if block_prev_headerhash != self._chain.blockchain[-1].headerhash:
                logger.warning('Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return False
        elif block.block_number - 1 not in self.blocks or block_prev_headerhash != self.blocks[block.block_number - 1][0].block.headerhash:
            logger.warning('Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
            return False

        if block.block_number in self.blocks and block_headerhash == self.blocks[block.block_number][0].block.headerhash:
            return False

        if (block.block_number - config.dev.reorg_limit) in self.blocks:
            self._move_to_mainchain(block.block_number - config.dev.reorg_limit)

        stake_reward = {}

        state_buffer = StateBuffer()

        # FIXME: Avoid +1/-1, assign a them to make things clear
        if block.block_number - 1 == self._chain.height():
            stake_validators_list = copy.deepcopy(self._chain.pstate.stake_validators_list)
            stxn_state = dict()
            # TODO: Optimization required
            if not self._state_add_block_buffer(block, stake_validators_list, stxn_state):
                logger.warning('State_validate_block failed inside chainbuffer #%d', block.block_number)
                return False

            block_buffer = BlockBuffer(block, stake_reward, self._chain, self.epoch_seed,
                                       self._get_st_balance(block.transactions[0].addr_from,
                                                            block.block_number))

            state_buffer.set_next_seed(block.reveal_hash, self.epoch_seed)
            state_buffer.stake_validators_list = stake_validators_list
            state_buffer.stxn_state = stxn_state
            state_buffer.update_stxn_state(self.height)
        else:
            block_state_buffer = self.blocks[block.block_number - 1]
            parent_state_buffer = block_state_buffer[1]
            parent_seed = block_state_buffer[1].next_seed

            stake_validators_list = copy.deepcopy(parent_state_buffer.stake_validators_list)
            stxn_state = copy.deepcopy(parent_state_buffer.stxn_state)
            if not self._state_add_block_buffer(block, stake_validators_list, stxn_state):
                logger.warning('State_validate_block failed inside chainbuffer #%s', block.block_number)
                return False
            block_buffer = BlockBuffer(block, stake_reward, self._chain, parent_seed,
                                       self._get_st_balance(block.transactions[0].addr_from,
                                                            block.block_number))
            state_buffer.stake_validators_list = stake_validators_list
            state_buffer.stxn_state = stxn_state
            state_buffer.update(self.height, parent_state_buffer, block)

        if block.block_number not in self.blocks:
            self.blocks[block.block_number] = [block_buffer, state_buffer]
        else:
            old_block_buffer = self.blocks[block.block_number][0]

            if block_buffer.score < old_block_buffer.score:
                self.blocks[block.block_number] = [block_buffer, state_buffer]
                if block.block_number + 1 in self.blocks:
                    self._remove_block(block.block_number + 1)
            elif block_buffer.score == old_block_buffer.score:  # When two blocks having equal score
                oldheaderhash = old_block_buffer.block.headerhash
                newheaderhash = block_buffer.block.headerhash
                if int(bin2hstr(newheaderhash), 16) < int(bin2hstr(oldheaderhash), 16):
                    self.blocks[block.block_number] = [block_buffer, state_buffer]
                    if block.block_number + 1 in self.blocks:
                        self._remove_block(block.block_number + 1)

        return True

    # TODO: This add_block used to be in state
    def add_block(self, block, ignore_save_wallet=False)->bool:
        # FIXME: This does not seem to be related to persistance
        address_txn = dict()
        self.load_address_state(block, address_txn)  # FIXME: Bottleneck

        # FIXME: Unify Genesis case inside update, otherwise the special case is scattered everywhere
        if block.block_number == 1:
            if not self._chain.pstate._update_genesis(self, block, address_txn):
                return False
        else:
            blocks_left = self.get_blocks_left(block.block_number)

            # FIXME: Verify this
            if len(block.transactions) < 1:
                logger.warning("Each block must contain at least a coinbase transaction")
                return False

            # FIXME: Handle the case where first_tx_from is not in sv_list
            first_tx_from = block.transactions[0].addr_from
            nonce = self._chain.pstate.stake_validators_list.sv_list[first_tx_from].nonce

            logger.debug('BLOCK: %s epoch: %s blocks_left: %s nonce: %s stake_selector %s',
                         block.block_number,
                         block.epoch,
                         blocks_left - 1,
                         nonce,
                         block.stake_selector)

            if not self._chain.pstate.update(block, self._chain.pstate.stake_validators_list, address_txn):
                return False

        self._commit(block,
                     address_txn,
                     wallet=self.wallet,
                     ignore_save_wallet=ignore_save_wallet)

        blocks_left = self.get_blocks_left(block.block_number)
        if blocks_left == 1:
            logger.info('EPOCH change:  updating PRF with updating wallet hashchains..')
            xmss = self.wallet.address_bundle[0].xmss
            tmphc = hashchain(xmss.get_seed_private(), epoch=block.epoch + 1)
            self.hash_chain = tmphc.hashchain

        self._chain.pstate._set_blockheight(self.height + 1)

        return True

    def _remove_block(self, blocknumber):
        if blocknumber not in self.blocks:
            return

        while blocknumber in self.blocks:
            del self.blocks[blocknumber]
            blocknumber += 1

    def load_address_state(self, block, address_txn):
        # FIXME: This does not seem to be related to persistance
        blocknumber = block.block_number

        for protobuf_tx in block.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.txfrom not in address_txn:
                # FIXME: Access to chain buffer from here
                address_txn[tx.txfrom] = self.get_stxn_state(blocknumber, tx.txfrom)

            if tx.subtype in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
                if tx.txto not in address_txn:
                    # FIXME: Access to chain buffer from here
                    address_txn[tx.txto] = self.get_stxn_state(blocknumber, tx.txto)

        # FIXME: Modifying input. Side effect, etc.
        return address_txn

    # Returns the number of blocks left before next epoch
    @staticmethod
    def get_blocks_left(blocknumber):
        epoch = blocknumber // config.dev.blocks_per_epoch
        blocks_left = blocknumber - (epoch * config.dev.blocks_per_epoch)
        blocks_left = config.dev.blocks_per_epoch - blocks_left
        return blocks_left

    def _commit(self,
                block: Block,
                address_txn,
                wallet: Wallet,
                ignore_save_wallet=False):

        # FIXME: This indexing approach is very inefficient
        staker = block.stake_selector
        self._chain.pstate.stake_validators_list.sv_list[staker].nonce += 1

        for address in address_txn:
            self._chain.pstate._save_address_state(address, address_txn[address])

        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in self._chain.pstate.stake_validators_list.sv_list:
                self._chain.pstate.stake_validators_list.sv_list[dup_tx.coinbase1.txto].is_banned = True

        if not ignore_save_wallet:
            wallet.save_wallet()

        self._chain.pstate.stake_validators_list.update_sv(block.block_number)

        logger.debug('%s %s tx passed verification.', bin2hstr(block.headerhash), len(block.transactions))
        return True

    def _commit(self, block, stake_validators_list):
        blocknumber = block.block_number
        blocks_left = self._chain.pstate._get_blocks_left(blocknumber)
        stake_validators_list.sv_list[block.stake_selector].nonce += 1
        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in stake_validators_list.sv_list:
                stake_validators_list.sv_list[dup_tx.coinbase1.txto].is_banned = True

        if blocks_left == 1:
            self._update_hash_chain(blocknumber)

        stake_validators_list.update_sv(blocknumber)

    def _state_add_block_buffer(self, block, stake_validators_list, address_txn):
        # FIXME: This is mixing states
        self.load_address_state(block, address_txn)

        is_successful = self._chain.pstate.update(block, stake_validators_list, address_txn)
        if is_successful:
            self._commit(block, stake_validators_list)
            logger.info('[ChainBuffer] Block #%s added  stake: %s', block.block_number,
                        block.stake_selector)

        return is_successful

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
                                 transactions=self.tx_pool.transaction_pool,
                                 duplicate_transactions=self.tx_pool.duplicate_tx_pool,
                                 signing_xmss=signing_xmss,
                                 nonce=nonce)

        slave_xmss = self.get_slave_xmss(last_block.block_number + 1)

        if not slave_xmss:
            return None     # FIXME: Not clear why the skip and return False

        # FIXME: Why is it necessary to access the wallet here? Unexpected side effect?
        self.wallet.save_slave(slave_xmss)

        return new_block

    def validate_block(self, block: Block)->bool:
        """
        Checks validity of a new block
        """
        try:
            # FIXME: review this.. Too complicated
            last_block = self.get_block(block.block_number - 1)

            if last_block is not None:          # FIXME: Review this
                if not block.blockheader.validate(last_block.blockheader):
                    return False

            if len(block.transactions) == 0:
                logger.warning('BLOCK : There must be atleast 1 txn')
                return False

            # Validate coinbase
            # FIXME: Check if it is possible to delegate validation to coinbase transaction. Why the code is in Block?
            coinbase_tx = CoinBase(block.transactions[0])

            if coinbase_tx.subtype != TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False

            if coinbase_tx.txto != block.blockheader.stake_selector:
                logger.info('Non matching txto and stake_selector')
                logger.info('txto: %s stake_selector %s', coinbase_tx.txfrom, block.stake_selector)
                return False

            if coinbase_tx.amount != block.blockheader.block_reward + block.blockheader.fee_reward:
                logger.info('Block_reward doesnt match')
                logger.info('Found: %s', coinbase_tx.amount)
                logger.info('Expected: %s', block.blockheader.block_reward + block.blockheader.fee_reward)
                logger.info('block_reward: %s', block.blockheader.block_reward)
                logger.info('fee_reward: %s', block.blockheader.fee_reward)
                return False

            if block.block_number == 1:
                found = False
                for protobuf_tx in block.transactions:
                    tx = Transaction.from_pbdata(protobuf_tx)
                    if tx.subtype == TX_SUBTYPE_STAKE:
                        if tx.txfrom == block.stake_selector:
                            found = True
                            reveal_hash = self._chain.select_hashchain(coinbase_tx.txto, tx.hash, blocknumber=1)
                            if sha256(bin2hstr(tuple(block.reveal_hash)).encode()) != reveal_hash:
                                logger.warning('reveal_hash does not hash correctly to terminator: failed validation')
                                return False

                if not found:
                    logger.warning('Stake selector not in block.stake: failed validation')
                    return False

            else:  # we look in stake_list for the hash terminator and hash to it..
                stake_validators_list = self.get_stake_validators_list(block.block_number)
                if coinbase_tx.txto not in stake_validators_list.sv_list:
                    logger.warning('Stake selector not in stake_list for this epoch..')
                    return False

                if not stake_validators_list.validate_hash(block.reveal_hash,
                                                           block.block_number,
                                                           coinbase_tx.txto):
                    logger.warning('Supplied hash does not iterate to terminator: failed validation')
                    return False

            if not self._validate_txs_in_block(block):
                logger.warning('Block validate_tx_in_block error: failed validation')
                return False

        except Exception as e:
            logger.exception(e)
            return False

        return True

    def _validate_txs_in_block(self, block: Block)->bool:
        # FIXME: This is accessing buffered chain. It does not belong here
        # Validating coinbase txn

        # FIXME: Again checking coinbase here?
        coinbase_txn = CoinBase(block.transactions[0])

        sv_list = self.stake_list_get(block.block_number)
        valid = coinbase_txn.validate_extended(sv_list=sv_list, blockheader=block.blockheader)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_num in range(1, len(block.transactions)):
            protobuf_tx = block.transactions[tx_num]
            tx = Transaction.from_pbdata(protobuf_tx)
            if not tx.validate():
                logger.warning('invalid tx in block')
                return False

        for protobuf_tx in block.duplicate_transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if not tx.validate():
                logger.warning('invalid duplicate tx in block')
                return False

        return True

    def _move_to_mainchain(self, blocknum)->bool:
        block = self.blocks[blocknum][0].block
        if not self.add_block(block):
            logger.info('last block failed state/stake checks, removed from chain')
            return False

        self._chain.blockchain.append(block)
        self._chain.remove_tx_in_block_from_pool(block)  # modify fn to keep transaction in memory till reorg
        self._chain.save_chain()

        self.epoch_seed = self.blocks[blocknum][1].next_seed

        self.epoch = int(blocknum // config.dev.blocks_per_epoch)

        self._clean_if_required(blocknum)

        del (self.blocks[blocknum])

        self._chain.pstate.update_last_tx(block)
        self._chain.pstate.update_tx_metadata(block)
        return True

    def get_block_n_score(self, blocknumber)->Optional[int]:
        try:
            return self.blocks[blocknumber][0].score
        except KeyError:
            logger.error('get_block_n_score, blocknumber not in self.blocks #%s', blocknumber)
        except Exception as e:
            logger.error('Unexpected Exception')
            logger.error('%s', e)
        return None

    def bkmr_tracking_blocknumber(self, ntp):
        last_block = self.get_last_block()

        if ntp.getTime() - last_block.timestamp >= config.dev.minimum_minting_delay - config.dev.timestamp_error:
            return last_block.block_number + 1

        return last_block.block_number

    def verify_BK_hash(self, block: Block, conn_identity)->bool:
        stake_selector = block.stake_selector
        prev_headerhash = block.prev_headerhash

        if block.block_number <= self._chain.height():
            return False

        sv_list = self.stake_list_get(block.block_number)

        if not sv_list:
            return False

        if stake_selector not in sv_list:
            return False

        if sv_list[stake_selector].is_banned:
            logger.warning('Rejecting block created by banned stake selector %s', stake_selector)
            return False

        if not sv_list[stake_selector].is_active:
            logger.warning('Rejecting block created by inactive stake selector %s', stake_selector)
            return False

        # FIXME: Avoid +1/-1, assign a them to make things clear
        if block.block_number - 1 == self._chain.height():
            if prev_headerhash != self._chain.blockchain[-1].headerhash:
                logger.warning('verify_BK_hash Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return False
            return True
        elif block.block_number - 1 not in self.blocks or prev_headerhash != self.blocks[block.block_number - 1][0].block.headerhash:
            logger.warning('verify_BK_hash Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
            return False

        stake_validators_list = self.get_stake_validators_list(block.block_number)

        if not stake_validators_list.validate_hash(block.reveal_hash,
                                                   block.block_number,
                                                   stake_address=stake_selector):
            logger.info('%s reveal doesnt hash to stake terminator reveal %s', conn_identity, block.reveal_hash)
            return False

        score = self.score_BK_hash(block)

        # FIXME: Unclear.. why verify checks ordering?
        return self._is_better_block(block.block_number, score)

    def score_BK_hash(self, block: Block)->int:
        seed = self._chain._get_epoch_seed(block.block_number)
        score = self._chain.score(stake_address=block.stake_selector,
                                  reveal_one=block.reveal_hash,
                                  balance=self._get_st_balance(block.stake_selector, block.block_number),
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
        if blocknum > self.height:
            return

        best_block = self.get_block(blocknum)

        if best_block.prev_headerhash != prev_blockheaderhash:
            return

        if best_block.stake_selector != stake_selector:
            return

        return True

    def _clean_if_required(self, blocknumber):
        """
        Checks if the mining data such as private_seeds, hash_chain, slave_xmss
        are no more required.
        :param blocknumber:
        :return:
        """
        prev_epoch = int((blocknumber - 1) // config.dev.blocks_per_epoch)

        sv_list = self._chain.pstate.stake_validators_list.sv_list
        if self.height in sv_list:
            activation_blocknumber = sv_list[self.height].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch == blocknumber:
                self._clean_mining_data(blocknumber - 1)
        elif prev_epoch != self.epoch:
            self._clean_mining_data(blocknumber - 1)

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
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
        tmp_chain = self._chain._read_chain(0)
        if len(tmp_chain) > 0:
            for block in tmp_chain[1:]:
                self.add_block_mainchain(block, validate=False)

        epoch = 1
        # FIXME: Avoid checking files here..
        while os.path.isfile(self._chain._get_chain_datafile(epoch)):
            del self._chain.blockchain[:-1]                                # FIXME: This optimization could be encapsulated
            for block in self._chain._read_chain(epoch):
                self.add_block_mainchain(block, validate=False)

            epoch += 1

        self.wallet.save_wallet()
        return self._chain.blockchain

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # Miscellaneous FIXME: Find a right location for this

    def search(self, query):
        # FIXME: Refactor this. Prepare a look up in the DB
        for tx in self.tx_pool.transaction_pool:
            if tx.txhash == query or tx.txfrom == query or tx.txto == query:
                logger.info('%s found in transaction pool..', query)
                return tx

        return self._chain.search(query)

    def error_msg(self, func_name, blocknum, exception=None):
        if exception:
            logger.error(func_name + ' Unknown exception at blocknum: %s', blocknum)
            logger.exception(exception)
            return

        logger.error('%s blocknum not found in blocks %s', func_name, blocknum)
        if self.blocks:
            logger.error('Min block num %s', min(self.blocks))
            logger.error('Max block num %s', max(self.blocks))

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # Slave xmss    FIXME: Connected to staking

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

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # Hashchain handling

    def hash_chain_get(self, blocknumber):
        epoch = self._get_mining_epoch(blocknumber)
        return self.hash_chain[epoch]

    def _update_hash_chain(self, blocknumber: int):
        epoch = int((blocknumber + 1) // config.dev.blocks_per_epoch)
        logger.info('Created new hash chain')

        prev_private_seed = self._wallet_private_seeds[epoch - 1]
        self._wallet_private_seeds[epoch] = prev_private_seed
        self.hash_chain[epoch] = hashchain(prev_private_seed, epoch=epoch).hashchain

    def select_hashchain(self, stake_address=None, hash_chain=None, blocknumber=None):
        # NOTE: Users POS / Block

        if not hash_chain:
            for s in self.stake_list_get(blocknumber):
                if s[0] == stake_address:
                    hash_chain = s[1]
                    break

        if not hash_chain:
            return

        return hash_chain

    def _get_epoch_seed(self, blocknumber: int)->Optional[int]:
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height():
                return int(str(self.epoch_seed), 16)

            return int(str(self.blocks[blocknumber - 1][1].next_seed), 16)
        except KeyError:
            self.error_msg('get_epoch_seed', blocknumber)
        except Exception as e:
            self.error_msg('get_epoch_seed', blocknumber, e)

        return None

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # Related to staking

    def create_stake_block(self, reveal_hash, last_block_number) -> Optional[Block]:
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        # FIXME: Break encapsulation
        t_pool2 = copy.deepcopy(self.tx_pool.transaction_pool)
        del self.tx_pool.transaction_pool[:]
        ######

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
                if tx.activation_blocknumber > self.height + config.dev.blocks_per_epoch + 1:
                    logger.debug('Skipping st as activation_blocknumber beyond limit')
                    logger.debug('Expected # less than : %s', (self.height + config.dev.blocks_per_epoch))
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

            self.tx_pool.add_tx_to_pool(tx)
            tx_nonce[tx.txfrom] += 1
            tx._data.nonce = self.get_stxn_state(last_block_number + 1, tx.txfrom)[0] + tx_nonce[tx.txfrom]
            txnum += 1

        # create the block..
        block_obj = self._chain.create_block(reveal_hash, last_block_number)

        # reset the pool back
        # FIXME: Reset pool from here?
        self.tx_pool.transaction_pool = copy.deepcopy(t_pool2)

        return block_obj

    def pubhashExists(self, addr, pubhash, blocknumber):
        # FIXME: Move to chain
        state_addr = self.get_stxn_state(blocknumber, addr)

        if state_addr is None:
            logger.info('-->> state_addr None not possible')
            return False

        if pubhash in state_addr[2]:
            return True

        return False

    def _get_mining_epoch(self, blocknumber):
        sv_list = self.stake_list_get(blocknumber)

        epoch = blocknumber // config.dev.blocks_per_epoch

        if sv_list and self.staking_address in sv_list:
            activation_blocknumber = sv_list[self.staking_address].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch > blocknumber:
                epoch = activation_blocknumber // config.dev.blocks_per_epoch

        return epoch

    def _get_st_balance(self, stake_address, blocknumber):
        if stake_address is None:
            logger.error('stake address should not be none, returning None')
            return None

        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height():
                if stake_address in self._chain.pstate.stake_validators_list.sv_list:
                    return self._chain.pstate.stake_validators_list.sv_list[stake_address].balance
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
                tmp_state = self._chain.pstate.get_address(addr)
                return tmp_state

            state_buffer = self.blocks[blocknumber - 1][1]

            if addr in state_buffer.stxn_state:
                return copy.deepcopy(state_buffer.stxn_state[addr])  # FIXME: Why deepcopy?

            return self._chain.pstate.get_address(addr)
        except KeyError:
            self.error_msg('get_stxn_state', blocknumber)
        except Exception as e:
            self.error_msg('get_stxn_state', blocknumber, e)

        return None

    def stake_list_get(self, blocknumber):
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 > self.height:
                return None

            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height():
                return self._chain.pstate.stake_validators_list.sv_list

            state_buffer = self.blocks[blocknumber - 1][1]

            return state_buffer.stake_validators_list.sv_list
        except KeyError:
            self.error_msg('stake_list_get', blocknumber)
        except Exception as e:
            self.error_msg('stake_list_get', blocknumber, e)

        return None

    def future_stake_addresses(self, blocknumber):
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height():
                return self._chain.pstate.stake_validators_list.future_stake_addresses

            state_buffer = self.blocks[blocknumber - 1][1]

            return state_buffer.stake_validators_list.future_stake_addresses
        except KeyError:
            self.error_msg('stake_list_get', blocknumber)
        except Exception as e:
            self.error_msg('stake_list_get', blocknumber, e)

        return None

    def get_stake_validators_list(self, blocknumber):
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height():
                return self._chain.pstate.stake_validators_list

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
