# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config, logger
from qrl.core.StateBuffer import StateBuffer
from qrl.core.BlockBuffer import BlockBuffer
from qrl.core.helper import json_bytestream, json_encode_complex, get_blocks_left
from qrl.crypto.misc import sha256

from copy import deepcopy

import gc

from qrl.crypto.hashchain import HashChain


class ChainBuffer:
    def __init__(self, chain):
        self.chain = chain
        self.state = self.chain.state
        self.blocks = dict()
        self.strongest_chain = dict()
        self.headerhashes = dict()
        self.size = config.dev.reorg_limit
        self.pending_blocks = dict()
        self.epoch = max(0, self.chain.height()) // config.dev.blocks_per_epoch  # Main chain epoch
        self.address_bundle_clone = dict()
        self.address_bundle_clone[self.epoch] = deepcopy(self.chain.address_bundle)
        self.epoch_seed = None
        self.hash_chain = dict()

        tmphc = HashChain(self.chain.address_bundle[0].xmss).hashchain()
        self.hash_chain[self.epoch] = tmphc.hashchain

        self.tx_buffer = dict()  # maintain the list of tx transaction that has been confirmed in buffer
        if self.chain.height() > 0:
            self.epoch = int(self.chain.m_blockchain[-1].blockheader.blocknumber / config.dev.blocks_per_epoch)

    def get_st_balance(self, stake_address, blocknumber):
        if stake_address is None:
            logger.info('stake address should not be none')
            raise Exception

        if blocknumber - 1 == self.chain.height():
            if stake_address in self.state.stake_validators_list.sv_list:
                return self.state.stake_validators_list.sv_list[stake_address].balance
            logger.info('Blocknumber not found')
            return None

        if blocknumber - 1 not in self.strongest_chain:
            logger.info('Blocknumber not in strongest chain')
            return None

        return self.strongest_chain[blocknumber - 1][1].stake_validators_list.sv_list[stake_address].balance

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

        tmp_address_bundle = deepcopy(self.address_bundle_clone[epoch - 1])
        self.address_bundle_clone[epoch] = tmp_address_bundle

        xmss = tmp_address_bundle[0].xmss
        tmp = HashChain(xmss).hashchain(epoch=epoch)
        self.hash_chain[epoch] = tmp.hashchain

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

    def add_block_mainchain(self, block, verify_block_reveal_list=True, validate=True, ignore_save_wallet=False):
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
                logger.info("Failed to add block by m_add_block, re-requesting the block #%s", blocknum)
                return
        else:
            if self.state.state_add_block(self.chain, block, ignore_save_wallet=True) is True:
                self.chain.m_blockchain.append(block)

        block_left = config.dev.blocks_per_epoch - (
            block.blockheader.blocknumber - (block.blockheader.epoch * config.dev.blocks_per_epoch))

        self.add_txns_buffer()
        if block_left == 1:  # As state_add_block would have already moved the next stake list to stake_list
            self.epoch_seed = self.state.stake_validators_list.calc_seed()
            self.address_bundle_clone[epoch + 1] = self.chain.address_bundle

            tmphc = HashChain(self.chain.address_bundle[0].xmss)
            self.hash_chain[epoch + 1] = tmphc.hashchain

            if epoch in self.address_bundle_clone:
                del self.address_bundle_clone[epoch]
        else:
            self.epoch_seed = sha256(block.blockheader.hash + str(self.epoch_seed))

        self.chain.update_last_tx(block)
        self.chain.update_tx_metadata(block)
        self.epoch = epoch
        return True

    def add_block(self, block):
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
            stake_validators_list = deepcopy(self.state.stake_validators_list)
            stxn_state = dict()
            # TODO: Optimization required
            if not self.state_add_block_buffer(block, stake_validators_list, stxn_state):
                logger.warning('State_validate_block failed inside chainbuffer #%d', block.blockheader.blocknumber)
                return

            block_buffer = BlockBuffer(block, stake_reward, self.chain, self.epoch_seed,
                                       self.get_st_balance(block.blockheader.stake_selector,
                                                           block.blockheader.blocknumber))

            state_buffer.set_next_seed(block.blockheader.hash, self.epoch_seed)
            state_buffer.stake_validators_list = stake_validators_list
            state_buffer.stxn_state = stxn_state
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
            stake_validators_list = deepcopy(parent_state_buffer.stake_validators_list)
            stxn_state = deepcopy(parent_state_buffer.stxn_state)
            if not self.state_add_block_buffer(block, stake_validators_list, stxn_state):
                logger.warning('State_validate_block failed inside chainbuffer #%d', block.blockheader.blocknumber)
                return
            block_buffer = BlockBuffer(block, stake_reward, self.chain, parent_seed,
                                       self.get_st_balance(block.blockheader.stake_selector,
                                                           block.blockheader.blocknumber))
            state_buffer.stake_validators_list = stake_validators_list
            state_buffer.stxn_state = stxn_state
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

        self.add_txns_buffer()

        return True

    def state_add_block_buffer(self, block, stake_validators_list, address_txn):
        self.chain.state.load_address_state(self.chain, block, address_txn)
        is_success = self.chain.state.state_update(block, stake_validators_list, address_txn)
        if is_success:
            self.commit(block.blockheader.blocknumber, stake_validators_list)

        return is_success

    def commit(self, blocknumber, stake_validators_list):
        blocks_left = get_blocks_left(blocknumber)

        if blocks_left == 1:
            stake_validators_list.move_next_epoch()
            self.update_hash_chain(blocknumber)

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
            return self.state.stake_validators_list.sv_list

        if blocknumber - 1 not in self.strongest_chain:
            logger.info('Stake list None')
            logger.info(('blocknumber #', blocknumber - 1, 'not found in strongest_chain'))
            return None

        stateBuffer = self.strongest_chain[blocknumber - 1][1]

        return stateBuffer.stake_validators_list.sv_list

    def next_stake_list_get(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return self.state.stake_validators_list.next_sv_list

        return self.strongest_chain[blocknumber - 1][1].stake_validators_list.next_sv_list

    def get_stake_validators_list(self, blocknumber):
        if blocknumber - 1 == self.chain.height():
            return self.state.stake_validators_list

        return self.strongest_chain[blocknumber - 1][1].stake_validators_list

    def get_threshold(self, blocknumber, staker_address):
        if blocknumber - 1 == self.chain.height():
            return self.state.stake_validators_list.get_threshold(staker_address)

        if blocknumber - 1 not in self.strongest_chain:
            logger.info('Stake list None')
            logger.info(('blocknumber #', blocknumber - 1, 'not found in strongest_chain'))
            return None

        stateBuffer = self.strongest_chain[blocknumber - 1][1]

        return stateBuffer.stake_validators_list.get_threshold(staker_address)

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
            if prev_epoch in self.address_bundle_clone:
                del self.address_bundle_clone[prev_epoch]
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
            transport.write(wrap_message('PB', json_bytestream(self.chain.m_get_block(blocknumber))))
        elif blocknumber in self.blocks:
            tmp = {blocknumber: []}
            for blockStateBuffer in self.blocks[blocknumber]:
                tmp[blocknumber].append(blockStateBuffer[0].block)
            transport.write(wrap_message('PBB', json_encode_complex(tmp)))

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
