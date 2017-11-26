# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
import os
from collections import defaultdict
from typing import Optional, Dict

from pyqrllib.pyqrllib import bin2hstr, XmssPool

from qrl.core import config, logger, Wallet, State
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.Chain import Chain
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.StakeValidatorsTracker import StakeValidatorsTracker
from qrl.core.VoteTracker import VoteTracker
from qrl.core.VoteMetadata import VoteMetadata
from qrl.core.Transaction import CoinBase, Transaction, Vote
from qrl.core.TransactionPool import TransactionPool
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.core.formulas import score, calc_seed
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2 import MR


# TODO: Rename to unstable/fluid chain or something similar?
class BufferedChain:
    def __init__(self, chain: Chain):
        self._chain = chain

        # [BlockBuffer, StateBuffer]
        self.blocks = dict()  # FIXME: Using a dict is very inefficient when index are a sequence

        self._pending_blocks = dict()

        self.epoch = max(0, self._chain.height) // config.dev.blocks_per_epoch  # Main chain epoch
        self.epoch_seed = None
        if self._chain.height > 0:
            self.epoch = self._chain.blockchain[-1].block_number // config.dev.blocks_per_epoch

        private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
        self._wallet_private_seeds = {self.epoch: private_seed}
        self.hash_chain = dict()
        self.hash_chain[self.epoch] = hashchain(private_seed).hashchain

        self.tx_pool = TransactionPool()  # FIXME: This is not stable, it should not be in chain

        self.stake_list = []

        self._vote_tracker = dict()  # Tracks votes, against blocknumber

        self.expected_headerhash = dict()

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
    def transaction_pool(self):
        return self.tx_pool.transaction_pool

    @property
    def length(self):
        return len(self._chain.blockchain)

    @property
    def height(self) -> int:
        if len(self.blocks) == 0:
            return self._chain.height
        return max(self.blocks.keys())  # FIXME: max over a dictionary?

    @property
    def pstate(self) -> State:
        return self._chain.pstate

    def set_voted(self, block_number):
        if block_number in self.blocks:
            block_metadata = self.blocks[block_number]
            block_metadata.set_voted()

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    # Block handling

    def add_pending_block(self, block) -> bool:
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

    def get_last_block(self) -> Optional[Block]:
        if len(self.blocks) == 0:
            return self._chain.get_last_block()

        # FIXME: Should this run max on the keys only? Or better keep track of the value..
        last_blocknum = max(self.blocks.keys())
        return self.blocks[last_blocknum].block

    def get_block(self, block_idx: int) -> Optional[Block]:
        if block_idx in self.blocks:
            return self.blocks[block_idx].block
        return self._chain.get_block(block_idx)

    def _move_to_mainchain(self) -> bool:
        if len(self.blocks) == 0:
            return True

        # FIXME: Simplify condition
        while len(self.blocks) > 0 and \
                (len(self.blocks) > config.dev.reorg_limit or min(self.blocks.keys()) == 0):

            # FIXME: self.blocks why a dict instead of a deque?
            block_idx = min(self.blocks.keys())
            block = self.blocks[block_idx].block
            stake_validators_tracker = self.blocks[block_idx].stake_validators_tracker

            if not self._add_block_mainchain(block, stake_validators_tracker):
                logger.info('Block {0} adding to stable chain failed'.format(block.block_number))
                return False

            if block.stake_selector == self.staking_address:
                logger.info('You won Block #%s!!!!!!!!!', block.block_number)

            # modify fn to keep transaction in memory till reorg
            self.tx_pool.remove_tx_in_block_from_pool(block)

            self.epoch_seed = self.blocks[block_idx].next_seed
            self.epoch = int(block_idx // config.dev.blocks_per_epoch)
            self._clean_if_required(block_idx)
            del self.blocks[block_idx]
            if block_idx in self._vote_tracker:
                del self._vote_tracker[block_idx]

            if block_idx in self.expected_headerhash:
                del self.expected_headerhash[block_idx]

        return True

    def _add_block_mainchain(self, block, stake_validators_tracker) -> bool:
        # FIXME: Reorganize/rewrite this after refactoring is stable. Crazy nesting
        if block.block_number == 1:
            self.initialize_chain(block)

        if not self._chain.add_block(block, stake_validators_tracker):
            logger.info("buff: Block {}. Add_block failed. Requesting again".format(block.block_number))
            self._validate_tx_pool()
            return False

        self.tx_pool.remove_tx_in_block_from_pool(block)

        # FIXME: clean this up
        block_left = config.dev.blocks_per_epoch
        block_left -= block.block_number - (block.epoch * config.dev.blocks_per_epoch)

        if block_left == 1:
            private_seed = self.wallet.address_bundle[0].xmss.get_seed_private()
            self._wallet_private_seeds[block.epoch + 1] = private_seed
            self.hash_chain[block.epoch + 1] = hashchain(private_seed, epoch=block.epoch + 1).hashchain

        self._clean_if_required(block.block_number)

        self.epoch_seed = sha256(block.reveal_hash + self.epoch_seed)

        self.epoch = block.epoch
        return True

    def add_lattice_public_key(self, lattice_public_key_txn):
        self._chain.pstate.put_lattice_public_key(lattice_public_key_txn)

    def add_vote(self, vote: Vote):
        if len(self._chain.blockchain) == 1 and vote.blocknumber != self.height:
            return

        if (self.height != 0 and vote.blocknumber <= self._chain.height) or vote.blocknumber > self.height:
            return

        height = self.height
        # FIXME: Temporary fix, need to add ST txn into genesis block
        if height > 1:
            stake_validators_tracker = self.get_stake_validators_tracker(height)

            if vote.addr_from not in stake_validators_tracker.sv_dict:
                logger.debug('Dropping Vote Txn, as %s not found in Stake Validator list', vote.addr_from)
                return

            if vote.blocknumber in self._vote_tracker:
                if self._vote_tracker[vote.blocknumber].is_already_voted(vote):
                    return

            tx_state = self.get_stxn_state(blocknumber=self.height, addr=vote.addr_from)

            if not (vote.validate() and vote.validate_extended(tx_state=tx_state, sv_dict=stake_validators_tracker.sv_dict)):
                logger.warning('>>>Vote %s invalid state validation failed..', bin2hstr(tuple(vote.txhash)))
                return

        if vote.blocknumber not in self._vote_tracker:
            self._vote_tracker[vote.blocknumber] = VoteTracker()

        # FIXME: Temporary fix, ST txn must be added into genesis
        if vote.blocknumber > 1:
            stake_validators_tracker = self.get_stake_validators_tracker(vote.blocknumber)
            stake_balance = stake_validators_tracker.get_stake_balance(vote.addr_from)
        else:
            genesis_block = self.get_block(0)
            for genesisBalance in genesis_block.genesis_balance:
                if genesisBalance.address.encode() == vote.addr_from:
                    stake_balance = genesisBalance.balance

        # FIXME: There is a warning that stake_balance coould be reference before assignment.
        return self._vote_tracker[vote.blocknumber].add_vote(vote, stake_balance)

    def get_consensus(self, blocknumber: int) -> Optional[VoteMetadata]:
        if blocknumber not in self._vote_tracker:
            return None

        return self._vote_tracker[blocknumber].get_consensus()

    def get_consensus_headerhash(self, blocknumber: int) -> Optional[bytes]:
        if blocknumber not in self._vote_tracker:
            return None

        return self._vote_tracker[blocknumber].get_consensus_headerhash()

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

    def initialize_chain(self, block_number_1: Block):
        # Initializes Required variables before adding blocknumber 1
        seed_list = []
        genesis_block = self.get_block(0)
        for raw_tx in block_number_1.transactions:
            tx = Transaction.from_pbdata(raw_tx)
            if tx.subtype == qrl_pb2.Transaction.STAKE:
                for genesisBalance in genesis_block.genesis_balance:
                    if tx.txfrom == genesisBalance.address.encode() and tx.activation_blocknumber == 1:
                        seed_list.append(tx.hash)
                        # FIXME: This goes to stake validator list without verification, Security Risk
                        self._chain.pstate.stake_validators_tracker.add_sv(genesisBalance.balance, tx, 1)

        self.epoch_seed = calc_seed(seed_list)

    def check_expected_headerhash(self, blocknumber: int, headerhash: bytes) -> bool:
        if blocknumber in self.expected_headerhash:
            if headerhash != self.expected_headerhash[blocknumber]:
                logger.warning('Consensus/Expected headerhash %s', self.expected_headerhash[blocknumber])
                logger.warning('Headerhash found %s', headerhash)
                return False

        return True

    def add_block(self, block: Block) -> bool:

        # is there an older version available?
        old_block_metadata = None
        if block.block_number in self.blocks:
            old_block_metadata = self.blocks[block.block_number]
            if old_block_metadata.isVoted:
                return False

        if block.block_number < self._chain.height:
            return False

        if not self.check_expected_headerhash(block.block_number, block.headerhash):
            logger.warning('Failed to Add block #%s', block.block_number)
            return False

        if block.block_number == 1:
            self._chain.pstate.stake_validators_tracker = StakeValidatorsTracker()
            self.initialize_chain(block)

        if not self.validate_block(block):  # This is here because of validators, etc
            logger.info('Block validation failed')
            logger.info('Block #%s', block.block_number)
            logger.info('Stake_selector %s', block.stake_selector)
            return False

        same_block = self.get_block(block.block_number)
        if same_block is not None and block.headerhash == same_block.headerhash:
            logger.debug('Block {}. already received'.format(block.block_number))
            return False

        prev_block = self.get_block(block.block_number - 1)
        block_balance = 0

        if block.block_number > 0:
            if prev_block is None:
                logger.warning('Prev_block is not available. Block {} rejected'.format(block.block_number))
                return False

            if prev_block.headerhash != block.prev_headerhash:
                logger.warning('buff: Block {} rejected. prev_block is not available.'.format(block.block_number))
                return False

            block_balance = self._get_st_balance(stake_address=block.transactions[0].addr_from,
                                                 block_number=block.block_number)

            if block_balance is None:
                logger.warning('main: Block {} rejected. prevheaderhash mismatch'.format(block.block_number))
                return False

        if block.block_number == 0 and self.epoch_seed is None:
            # FIXME: A proper epoch seed should be already available for the genesis block
            logger.error("epoch seed is None for the genesis block!!!!!")
            self.epoch_seed = sha256(b'INVALID_EPOCH_SEED')

        # Prepare Metadata inputs

        if block.block_number == 0 or self._chain.height + 1 == block.block_number:
            prev_sv_tracker = copy.deepcopy(self._chain.pstate.stake_validators_tracker)
            address_state_dict = dict()
            hash_chain = None
            seed = self.epoch_seed
        else:
            prev_block_metadata = self.blocks[block.block_number - 1]
            prev_sv_tracker = copy.deepcopy(prev_block_metadata.stake_validators_tracker)
            address_state_dict = copy.deepcopy(prev_block_metadata.address_state_dict)
            hash_chain = copy.deepcopy(prev_block_metadata.hash_chain)
            seed = prev_block_metadata.next_seed

        for raw_vote in block.vote:
            vote = Transaction.from_pbdata(raw_vote)
            self.add_vote(vote)

        if block.block_number > 0:
            voteMetadata = self.get_consensus(block.block_number - 1)
            consensus_headerhash = self.get_consensus_headerhash(block.block_number - 1)

            consensus_ratio = voteMetadata.total_stake_amount / prev_sv_tracker.get_total_stake_amount()

            if consensus_ratio < 0.51:
                logger.warning('Block #%s Rejected, Consensus lower than 51%%..', block.block_number)
                logger.warning('%s/%s', voteMetadata.total_stake_amount, prev_sv_tracker.get_total_stake_amount())
                return False
            elif consensus_headerhash != prev_block.headerhash:
                logger.warning('Consensus headerhash doesnt match')
                logger.warning('Consensus Previous Headerhash %s', consensus_headerhash)
                logger.warning('Current Previous Headerhash %s', prev_block.headerhash)
                logger.warning('Previous blocknumber #%s', prev_block.block_number)
                # TODO: Fork Recovery Logic
                return False

        if not self._state_add_block_buffer(block, prev_sv_tracker, address_state_dict):
            logger.warning('State_validate_block failed inside chainbuffer #%s', block.block_number)
            return False

        block_metadata = BlockMetadata(block=block,
                                       hash_chain=hash_chain,
                                       epoch_seed=seed,
                                       balance=block_balance)

        block_metadata.stake_validators_tracker = prev_sv_tracker
        block_metadata.address_state_dict = address_state_dict
        block_metadata.update_stxn_state(self._chain.pstate)

        # add/replace if new option is better
        if old_block_metadata is None or block_metadata.sorting_key < old_block_metadata.sorting_key:
            self.blocks[block.block_number] = block_metadata
            self._remove_blocks(block.block_number + 1)

        # Move to stable chain if necessary
        return self._move_to_mainchain()

    def _update(self,
                block: Block,
                stake_validators_tracker: StakeValidatorsTracker,
                address_txn: Dict[bytes, AddressState]) -> bool:

        if block.block_number > 0:
            if block.stake_selector not in stake_validators_tracker.sv_dict:
                logger.warning('stake selector not in stake_list_get')
                return False

            if stake_validators_tracker.sv_dict[block.stake_selector].is_banned:
                logger.warning('stake selector is in banned list')
                return False

            if not stake_validators_tracker.sv_dict[block.stake_selector].is_active:
                logger.warning('stake selector is in inactive')
                return False

        # FIX ME : Temporary fix, to include only either ST txn or TransferCoin txn for an address
        stake_txn = set()
        transfercoin_txn = set()
        destake_txn = set()

        # cycle through every tx in the new block to check state
        for protobuf_tx in block.transactions:
            # FIXME: Simplify this.. too complex. delegate to objects, etc.

            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.subtype == qrl_pb2.Transaction.COINBASE:
                expected_nonce = stake_validators_tracker.sv_dict[tx.txfrom].nonce + 1
            else:
                expected_nonce = address_txn[tx.txfrom].nonce + 1

            if tx.nonce != expected_nonce:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.subtype)
                logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, expected_nonce)
                return False

            # TODO: To be fixed later
            if tx.pubhash in address_txn[tx.txfrom].pubhashes:
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.subtype)
                return False

            if tx.subtype == qrl_pb2.Transaction.TRANSFER:
                if tx.txfrom in stake_txn:
                    logger.warning("Transfer coin done by %s address is a Stake Validator", tx.txfrom)
                    return False

                if tx.txfrom in stake_validators_tracker.sv_dict and stake_validators_tracker.sv_dict[
                        tx.txfrom].is_active:
                    logger.warning("Source address is a Stake Validator, balance is locked while staking")
                    return False

                if (tx.txfrom in stake_validators_tracker.future_stake_addresses and
                        stake_validators_tracker.future_stake_addresses[tx.txfrom].is_active):
                    logger.warning("Source address is in Future Stake Validator List, balance is locked")
                    return False

                if address_txn[tx.txfrom].balance < tx.amount:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s', address_txn[tx.txfrom].balance, tx.amount)
                    return False

                transfercoin_txn.add(tx.txfrom)

            elif tx.subtype == qrl_pb2.Transaction.STAKE:
                if tx.txfrom in transfercoin_txn:
                    logger.warning('Block cannot have both st txn & transfer coin txn from same address %s', tx.txfrom)
                    return False
                if tx.txfrom in stake_txn:
                    logger.warning('Block cannot have multiple Stake Txn from same address %s', tx.txfrom)
                    return False
                if tx.txfrom in destake_txn:
                    logger.warning('Block may not have both Stake and Destake txn of same address %s', tx.txfrom)
                    return False

                if tx.txfrom in stake_validators_tracker.sv_dict:
                    expiry = stake_validators_tracker.sv_dict[tx.txfrom].activation_blocknumber + \
                        config.dev.blocks_per_epoch

                    if block.block_number > 1 and tx.activation_blocknumber < expiry:
                        logger.warning('Failed %s is already active for the given range', tx.txfrom)
                        return False

                    activation_limit = block.block_number + config.dev.blocks_per_epoch + 1

                    if tx.activation_blocknumber > activation_limit:
                        logger.warning('Failed %s activation_blocknumber beyond limit', tx.txfrom)
                        logger.warning('Found %s', tx.activation_blocknumber)
                        logger.warning('Must be less than %s', tx.activation_limit)
                        return False

                future_stake_addresses = stake_validators_tracker.future_stake_addresses

                if tx.txfrom not in future_stake_addresses:
                    if tx.txfrom in address_txn:
                        balance = address_txn[tx.txfrom].balance
                    else:
                        balance = self._chain.pstate._get_address_state(tx.txfrom).balance

                    stake_validators_tracker.add_sv(balance, tx, block.block_number)

                stake_txn.add(tx.txfrom)

            elif tx.subtype == qrl_pb2.Transaction.DESTAKE:
                if tx.txfrom in stake_txn:
                    logger.warning('Block may not have both Destake and Stake txn of same address %s', tx.txfrom)
                    return False

                if tx.txfrom in destake_txn:
                    logger.warning('Block cannot have multiple Destake Txn from same address %s', tx.txfrom)
                    return False

                if tx.txfrom not in stake_validators_tracker.sv_dict and tx.txfrom not in stake_validators_tracker.future_stake_addresses:
                    logger.warning('Failed due to destake %s is not a stake validator', tx.txfrom)
                    return False

                if tx.txfrom in stake_validators_tracker.sv_dict:
                    stake_validators_tracker.sv_dict[tx.txfrom]._is_active = False

                if tx.txfrom in stake_validators_tracker.future_stake_addresses:
                    stake_validators_tracker.future_stake_addresses[tx.txfrom].is_active = False

                destake_txn.add(tx.txfrom)

            if tx.subtype != qrl_pb2.Transaction.COINBASE:
                address_txn[tx.txfrom].increase_nonce()

            if tx.subtype == qrl_pb2.Transaction.TRANSFER:
                address_txn[tx.txfrom].balance -= tx.amount - tx.fee

            if tx.subtype in (qrl_pb2.Transaction.TRANSFER, qrl_pb2.Transaction.COINBASE):
                address_txn[tx.txto].balance += tx.amount

            address_txn[tx.txfrom].pubhashes.append(tx.pubhash)

        return True

    def remove_last_buffer_block(self):
        last_block_number = self.height
        self._remove_blocks(last_block_number)

    def _remove_blocks(self, starting_blocknumber: int):
        if starting_blocknumber not in self.blocks:
            return

        while starting_blocknumber in self.blocks:
            del self.blocks[starting_blocknumber]
            starting_blocknumber += 1

    def load_address_state(self, block: Block,
                           address_txn: Dict[bytes, AddressState]) -> Dict[bytes, AddressState]:

        for protobuf_tx in block.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.txfrom not in address_txn:
                # FIXME: Access to chain buffer from here
                address_txn[tx.txfrom] = self.get_stxn_state(block.block_number, tx.txfrom)

            if tx.subtype in (qrl_pb2.Transaction.TRANSFER, qrl_pb2.Transaction.COINBASE):
                if tx.txto not in address_txn:
                    # FIXME: Access to chain buffer from here
                    address_txn[tx.txto] = self.get_stxn_state(block.block_number, tx.txto)

        # FIXME: Modifying input. Side effect, etc.
        return address_txn

    # Returns the number of blocks left before next epoch
    @staticmethod
    def get_blocks_left(blocknumber: int) -> int:
        epoch = blocknumber // config.dev.blocks_per_epoch
        blocks_left = blocknumber - (epoch * config.dev.blocks_per_epoch)
        blocks_left = config.dev.blocks_per_epoch - blocks_left
        return blocks_left

    def _commit(self,
                block: Block,
                address_state_dict: Dict[bytes, AddressState],
                wallet: Wallet,
                ignore_save_wallet=False):

        # FIXME: This indexing approach is very inefficient
        staker = block.stake_selector
        self._chain.pstate.stake_validators_tracker.sv_dict[staker].increase_nonce()

        for address in address_state_dict:
            self._chain.pstate._save_address_state(address_state_dict[address])

        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in self._chain.pstate.stake_validators_tracker.sv_dict:
                # FIXME: Setting the property is invalid
                self._chain.pstate.stake_validators_tracker.sv_dict[dup_tx.coinbase1.txto]._is_banned = True

        if not ignore_save_wallet:
            wallet.save_wallet()

        self._chain.pstate.stake_validators_tracker.update_sv(block.block_number)

        logger.debug('%s %s tx passed verification.', bin2hstr(block.headerhash), len(block.transactions))
        return True

    def _state_add_block_buffer(self,
                                block: Block,
                                stake_validators_tracker: StakeValidatorsTracker,
                                address_state_dict: Dict[bytes, AddressState]):

        # FIXME: This is mixing states
        address_state_dict = self.load_address_state(block, address_state_dict)

        is_successful = self._update(block, stake_validators_tracker, address_state_dict)

        if is_successful:
            if block.block_number > 0:
                stake_validators_tracker.sv_dict[block.stake_selector].increase_nonce()

                for dup_tx in block.duplicate_transactions:
                    if dup_tx.coinbase1.txto in stake_validators_tracker.sv_dict:
                        # FIXME: Setting the property is invalid
                        stake_validators_tracker.sv_dict[dup_tx.coinbase1.txto]._is_banned = True

                if self.get_blocks_left(block.block_number) == 1:
                    # UPDATE HASHCHAIN
                    epoch = int((block.block_number + 1) // config.dev.blocks_per_epoch)
                    logger.info('Created new hash chain')

                    prev_private_seed = self._wallet_private_seeds[epoch - 1]
                    self._wallet_private_seeds[epoch] = prev_private_seed
                    self.hash_chain[epoch] = hashchain(prev_private_seed, epoch=epoch).hashchain

                stake_validators_tracker.update_sv(block.block_number)

            logger.info('[ChainBuffer] Block #%s added  stake: %s', block.block_number, block.stake_selector)

        return is_successful

    def create_block(self,
                     reveal_hash: bytes,
                     last_block_number: int = -1) -> Optional[Block]:

        # FIXME: This can probably happen inside get_block, why two methods?
        if last_block_number == -1:
            last_block = self.get_last_block()
        else:
            last_block = self.get_block(last_block_number)
        # FIXME

        signing_xmss = self.get_slave_xmss(last_block.block_number + 1)
        sv_dict = self.get_stake_validators_tracker(last_block.block_number + 1).sv_dict
        nonce = sv_dict[self.staking_address].nonce + 1

        new_block = Block.create(staking_address=self.staking_address,
                                 block_number=last_block.block_number + 1,
                                 reveal_hash=reveal_hash,
                                 prevblock_headerhash=last_block.headerhash,
                                 transactions=self.tx_pool.transaction_pool,
                                 duplicate_transactions=self.tx_pool.duplicate_tx_pool,
                                 vote=self._vote_tracker[last_block.block_number].get_consensus(),
                                 signing_xmss=signing_xmss,
                                 nonce=nonce)

        slave_xmss = self.get_slave_xmss(last_block.block_number + 1)

        if not slave_xmss:
            return None  # FIXME: Not clear why the skip and return False

        # FIXME: Why is it necessary to access the wallet here? Unexpected side effect?
        self.wallet.save_slave(slave_xmss)

        return new_block

    def validate_block(self, block: Block) -> bool:
        """
        Checks validity of a new block
        """
        try:
            # FIXME: review this.. Too complicated
            last_block = self.get_block(block.block_number - 1)

            if last_block is not None:  # FIXME: Review this
                if not block.blockheader.validate(last_block.blockheader):
                    return False

            if last_block is None and block.block_number == 0:
                return block == GenesisBlock()

            if len(block.transactions) == 0:
                logger.warning('BLOCK : There must be atleast 1 txn')
                return False

            # Validate coinbase
            # FIXME: Check if it is possible to delegate validation to coinbase transaction. Why the code is in Block?
            coinbase_tx = Transaction.from_pbdata(block.transactions[0])

            if coinbase_tx.subtype != qrl_pb2.Transaction.COINBASE:
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
                    if tx.subtype == qrl_pb2.Transaction.STAKE:
                        if tx.txfrom == block.stake_selector:
                            found = True
                            reveal_hash = self.select_hashchain(coinbase_tx.txto, tx.hash, blocknumber=1)
                            if sha256(block.reveal_hash) != reveal_hash:
                                logger.warning('reveal_hash does not hash correctly to terminator: failed validation')
                                return False

                if not found:
                    logger.warning('Stake selector not in block.stake: failed validation')
                    return False

            else:  # we look in stake_list for the hash terminator and hash to it..
                stake_validators_tracker = self.get_stake_validators_tracker(block.block_number)
                if coinbase_tx.txto not in stake_validators_tracker.sv_dict:
                    logger.warning('Stake selector not in stake_list for this epoch..')
                    return False

                if not stake_validators_tracker.validate_hash(block.reveal_hash,
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

    def _validate_txs_in_block(self, block: Block) -> bool:
        # FIXME: This is accessing buffered chain. It does not belong here
        # Validating coinbase txn

        # FIXME: Again checking coinbase here?
        coinbase_txn = CoinBase(block.transactions[0])

        sv_dict = self.stake_list_get(block.block_number)
        valid = coinbase_txn.validate_extended(sv_dict=sv_dict, blockheader=block.blockheader)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_pbdata in block.transactions[1:]:
            tx = Transaction.from_pbdata(tx_pbdata)
            if not tx.validate():
                logger.warning('invalid tx in block')
                return False

        for tx_pbdata in block.duplicate_transactions:
            tx = Transaction.from_pbdata(tx_pbdata)
            if not tx.validate():
                logger.warning('invalid duplicate tx in block')
                return False

        return True

    def get_block_score(self, blocknumber) -> Optional[int]:
        try:
            return self.blocks[blocknumber].score
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

    def verify_BK_hash(self, mr_data: MR, conn_identity) -> bool:
        stake_selector = mr_data.stake_selector
        prev_headerhash = mr_data.prev_headerhash

        if mr_data.block_number <= self._chain.height:
            return False

        sv_dict = self.stake_list_get(mr_data.block_number)

        if not sv_dict:
            return False

        if stake_selector not in sv_dict:
            return False

        if sv_dict[stake_selector].is_banned:
            logger.warning('Rejecting block created by banned stake selector %s', stake_selector)
            return False

        if not sv_dict[stake_selector].is_active:
            logger.warning('Rejecting block created by inactive stake selector %s', stake_selector)
            return False

        # FIXME: Avoid +1/-1, assign a them to make things clear
        if mr_data.block_number - 1 == self._chain.height:
            if prev_headerhash != self._chain.blockchain[-1].headerhash:
                logger.warning('verify_BK_hash Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
                return False
            return True
        elif mr_data.block_number - 1 not in self.blocks or prev_headerhash != self.blocks[mr_data.block_number - 1]\
                .block.headerhash:
            logger.warning('verify_BK_hash Failed due to prevheaderhash mismatch, blockslen %d', len(self.blocks))
            return False

        stake_validators_tracker = self.get_stake_validators_tracker(mr_data.block_number)

        if not stake_validators_tracker.validate_hash(mr_data.reveal_hash,
                                                      mr_data.block_number,
                                                      stake_address=stake_selector):
            logger.info('%s reveal doesnt hash to stake terminator reveal %s', conn_identity, mr_data.reveal_hash)
            return False

        score = self.score_BK_hash(mr_data)

        # FIXME: Unclear.. why verify checks ordering?
        return self._is_better_block(mr_data.block_number, score)

    def score_BK_hash(self, block: Block) -> int:
        seed = self._get_epoch_seed(block.block_number)

        # FIXME: Duplicated code
        return score(stake_address=block.stake_selector,
                     reveal_one=block.reveal_hash,
                     balance=self._get_st_balance(block.stake_selector, block.block_number),
                     seed=seed)

    def _is_better_block(self, block_idx: int, score: float)->bool:
        if block_idx not in self.blocks:
            return True

        oldscore = self.blocks[block_idx].score

        if score < oldscore:
            return True

        return False

    def is_duplicate_block(self,
                           block_idx: int,
                           prev_headerhash: bytes,
                           stake_selector)->bool:
        """
        A block is considered as a dirty block, if same stake validator created two different blocks
        for the same blocknumber having same prev_blockheaderhash.
        """
        if block_idx > self.height:
            return False

        best_block = self.get_block(block_idx)

        if best_block.prev_headerhash != prev_headerhash:
            return False

        if best_block.stake_selector != stake_selector:
            return False

        return True

    def _clean_if_required(self, block_idx):
        """
        Checks if the mining data such as private_seeds, hash_chain, slave_xmss
        are no more required.
        :param block_idx:
        :return:
        """
        prev_epoch = int((block_idx - 1) // config.dev.blocks_per_epoch)

        sv_dict = self._chain.pstate.stake_validators_tracker.sv_dict
        if self.height in sv_dict:
            activation_blocknumber = sv_dict[self.height].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch == block_idx:
                self._clean_mining_data(block_idx - 1)
        elif prev_epoch != self.epoch:
            self._clean_mining_data(block_idx - 1)

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # TODO: Persistence will move to rocksdb

    def load(self):
        logger.info('Reading chain..')

        # TODO: Persistence will move to rocksdb
        self._chain.blockchain = []

        # FIXME: Adds an empty block, later ignores and overwrites.. A complete genesis block should be here
        self._chain.pstate.zero_all_addresses()
        genesis_block = GenesisBlock()

        # FIXME: This should happen when the block is added to the main chain
        for genesis_balance in genesis_block.genesis_balance:
            genesis_address = genesis_balance.address.encode()
            address_state = AddressState.create(address=genesis_address,
                                                nonce=config.dev.default_nonce,
                                                balance=genesis_balance.balance,
                                                pubhashes=[])
            self._chain.pstate._save_address_state(address_state)
        ###########

        # FIXME: Direct access - Breaks encapsulation
        self._chain.blockchain.append(genesis_block)  # FIXME: Adds without checking???

        # FIXME: it is not nice how genesis block is ignored
        tmp_chain = self._chain._read_chain(0)
        if len(tmp_chain) > 0:
            for block in tmp_chain[1:]:
                self.add_block(block)

        epoch = 1
        # FIXME: Avoid checking files here..
        while os.path.isfile(self._chain._get_chain_datafile(epoch)):
            del self._chain.blockchain[:-1]  # FIXME: This optimization could be encapsulated
            for block in self._chain._read_chain(epoch):
                self.add_block(block)

            epoch += 1

        self.wallet.save_wallet()
        logger.info('{} blocks'.format(self.length))
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

    def select_hashchain(self,
                         stake_address: bytes = None,
                         hash_chain=None,
                         blocknumber=None):

        # NOTE: Users POS / Block

        if not hash_chain:
            for s in self.stake_list_get(blocknumber):
                if s[0] == stake_address:
                    hash_chain = s[1]
                    break

        if not hash_chain:
            return

        return hash_chain

    def _get_epoch_seed(self, blocknumber: int) -> Optional[bytes]:
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height:
                return self.epoch_seed

            return self.blocks[blocknumber - 1].next_seed
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
        stake_validators_tracker = self.get_stake_validators_tracker(last_block_number + 1)
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

            if tx.subtype == qrl_pb2.Transaction.TRANSFER:
                if tx.txfrom in stake_txn:
                    logger.debug("Txn dropped: %s address is a Stake Validator", tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if tx.txfrom in stake_validators_tracker.sv_dict and stake_validators_tracker.sv_dict[
                        tx.txfrom].is_active:
                    logger.debug("Txn dropped: %s address is a Stake Validator", tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if (tx.txfrom in stake_validators_tracker.future_stake_addresses and
                        stake_validators_tracker.future_stake_addresses[tx.txfrom].is_active):
                    logger.debug("Txn dropped: %s address is in Future Stake Validator", tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                transfercoin_txn.add(tx.txfrom)

            if tx.subtype == qrl_pb2.Transaction.STAKE:
                if tx.txfrom in stake_validators_tracker.future_stake_addresses:
                    logger.debug('P2P dropping st as staker is already in future_stake_address %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if tx.txfrom in stake_validators_tracker.sv_dict:
                    expiry = stake_validators_tracker.sv_dict[
                        tx.txfrom].activation_blocknumber + config.dev.blocks_per_epoch
                    if tx.activation_blocknumber < expiry:
                        logger.debug('P2P dropping st txn as it is already active for the given range %s', tx.txfrom)
                        del t_pool2[txnum]
                        total_txn -= 1
                        continue

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
                if tx.txfrom in stake_validators_tracker.future_stake_addresses:
                    logger.debug('Skipping st as staker is already in future_stake_address')
                    logger.debug('Staker address : %s', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue
                if tx.txfrom in stake_validators_tracker.sv_dict:
                    expiry = stake_validators_tracker.sv_dict[
                        tx.txfrom].activation_blocknumber + config.dev.blocks_per_epoch
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

            if tx.subtype == qrl_pb2.Transaction.DESTAKE:
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
                if tx.txfrom not in stake_validators_tracker.sv_dict and tx.txfrom not in stake_validators_tracker.future_stake_addresses:
                    logger.debug('Dropping destake txn as %s not found in stake validator list', tx.txfrom)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                destake_txn.add(tx.txfrom)

            self.tx_pool.add_tx_to_pool(tx)
            tx_nonce[tx.txfrom] += 1
            tx._data.nonce = self.get_stxn_state(last_block_number + 1, tx.txfrom).nonce + tx_nonce[tx.txfrom]
            txnum += 1

        # create the block..
        block_obj = self.create_block(reveal_hash, last_block_number)

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

        if pubhash in state_addr.pubhashes:
            return True

        return False

    def _get_mining_epoch(self, blocknumber):
        sv_dict = self.stake_list_get(blocknumber)

        epoch = blocknumber // config.dev.blocks_per_epoch

        if sv_dict and self.staking_address in sv_dict:
            activation_blocknumber = sv_dict[self.staking_address].activation_blocknumber
            if activation_blocknumber + config.dev.blocks_per_epoch > blocknumber:
                epoch = activation_blocknumber // config.dev.blocks_per_epoch

        return epoch

    def _get_st_balance(self, stake_address, block_number) -> Optional[int]:
        if stake_address is None:
            logger.error('stake address should not be none, returning None')
            return None

        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if block_number - 1 == self._chain.height:
                if stake_address in self._chain.pstate.stake_validators_tracker.sv_dict:
                    return self._chain.pstate.stake_validators_tracker.sv_dict[stake_address].balance
                logger.info('Blocknumber not found')
                return None

            return self.blocks[block_number - 1].stake_validators_tracker.sv_dict[stake_address].balance
        except KeyError:
            self.error_msg('get_st_balance', block_number)
        except Exception as e:
            self.error_msg('get_st_balance', block_number, e)

        return None

    def get_stxn_state(self, blocknumber, addr) -> Optional[AddressState]:
        try:
            # FIXME: Simplify this - self.blocks[blocknumber - 1][1] is a StateBuffer
            if blocknumber - 1 == self._chain.height or addr not in self.blocks[blocknumber - 1].address_state_dict:
                address_state = self._chain.pstate.get_address(addr)
                return address_state

            if addr in self.blocks[blocknumber - 1].address_state_dict:
                return copy.deepcopy(self.blocks[blocknumber - 1].address_state_dict[addr])  # FIXME: Why deepcopy?

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
            if blocknumber - 1 == self._chain.height or blocknumber <= 1:
                return self._chain.pstate.stake_validators_tracker.sv_dict

            return self.blocks[blocknumber - 1].stake_validators_tracker.sv_dict
        except KeyError:
            self.error_msg('stake_list_get', blocknumber)
        except Exception as e:
            self.error_msg('stake_list_get', blocknumber, e)

        return None

    def future_stake_addresses(self, blocknumber):
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if blocknumber - 1 == self._chain.height:
                return self._chain.pstate.stake_validators_tracker.future_stake_addresses

            return self.blocks[blocknumber - 1].stake_validators_tracker.future_stake_addresses
        except KeyError:
            self.error_msg('stake_list_get', blocknumber)
        except Exception as e:
            self.error_msg('stake_list_get', blocknumber, e)

        return None

    def get_stake_validators_tracker(self, block_idx: int) -> Optional[StakeValidatorsTracker]:
        try:
            # FIXME: Avoid +1/-1, assign a them to make things clear
            if block_idx - 1 == self._chain.height:
                return self._chain.pstate.stake_validators_tracker

            return self.blocks[block_idx - 1].stake_validators_tracker
        except KeyError:
            self.error_msg('get_stake_validators_tracker', block_idx)
        except Exception as e:
            self.error_msg('get_stake_validators_tracker', block_idx, e)

        return None

    def _clean_mining_data(self, blocknumber):
        """
        Removes the mining data from the memory.
        :param blocknumber:
        :return:
        """

        prev_epoch = blocknumber // config.dev.blocks_per_epoch
        prev_prev_epoch = prev_epoch - 1

        if prev_prev_epoch in self._wallet_private_seeds:
            del self._wallet_private_seeds[prev_prev_epoch]

        if prev_prev_epoch in self.hash_chain:
            del self.hash_chain[prev_prev_epoch]

        # FIXME: This should not be here
        if prev_prev_epoch in self.slave_xmss:
            del self.slave_xmss[prev_prev_epoch]
