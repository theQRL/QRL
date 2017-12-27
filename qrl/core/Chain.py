# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from enum import Enum
from typing import Optional, Dict, Callable

from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.StakeValidatorsTracker import StakeValidatorsTracker
from qrl.core.AddressState import AddressState
from qrl.core.Transaction import Transaction
from qrl.core.notification.Observable import Observable
from qrl.core.notification.ObservableEvent import ObservableEvent


class ChainEvent(ObservableEvent):
    def __init__(self, event_id, block: Block):
        super().__init__(event_id)
        self._block = block

    @property
    def block(self):
        return self.block


class Chain:
    class EventType(Enum):
        BLOCK_COMMIT = 1

    def __init__(self, state):
        self.pstate = state  # FIXME: Is this really a parameter?
        self.blockchain = []  # FIXME: Everyone is touching this

        self._observable = Observable(self)

    def register(self, message_type: EventType, func: Callable):
        self._observable.register(message_type, func)

    @property
    def height(self):
        # FIXME: This will probably get replaced with rocksdb
        if len(self.blockchain):
            return self.blockchain[-1].block_number
        return 0

    def add_block(self,
                  block: Block,
                  address_state_dict: Dict[bytes, AddressState],
                  next_seed) -> bool:
        # TODO : minimum block validation in unsynced _state
        if block.block_number < self.height:
            logger.warning("Block already in the chain")
            return False

        if self.height > 0:
            prev_block = self.blockchain[-1]
            if block.block_number != prev_block.block_number + 1:
                logger.warning('main: Block {} rejected. prev_block is not available.'.format(block.block_number))
                return False

            if prev_block.headerhash != block.prev_headerhash:
                logger.warning('main: Block {} rejected. prevheaderhash mismatch'.format(block.block_number))
                return False

        logger.debug('%s %s tx passed verification.', block.headerhash, len(block.transactions))

        # COMMIT THE BLOCK

        # FIXME: Check the logic behind these operations
        self.blockchain.append(block)

        # FIXME: Use a context manager for db get_batch
        batch = self.pstate.get_batch()

        self.pstate.update_vote_metadata(block, batch)  # This has to be updated, before the pstate stake_validators

        for address in address_state_dict:
            self.pstate._save_address_state(address_state_dict[address], batch)

        self._observable.notify(ChainEvent(self.EventType.BLOCK_COMMIT, block))

        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in self.pstate.stake_validators_tracker.sv_dict:
                # FIXME: Setting the property is invalid
                self.pstate.stake_validators_tracker.sv_dict[dup_tx.coinbase1.txto].Ban()

        # This looks more like optimization/caching
        self.pstate.update_last_tx(block, batch)
        self.pstate.update_tx_metadata(block, batch)
        self.pstate.write_stake_validators_tracker(batch)
        self.pstate.write_prev_stake_validators_tracker(batch)
        self.pstate.update_next_seed(next_seed, batch)
        self.pstate.update_state_version(block.block_number, batch)
        self.pstate.put_block(block, batch)

        self.pstate.write_batch(batch)

        logger.debug('#%s[%s]\nWinner Stake Selector: %s has been committed.',
                     block.block_number,
                     block.headerhash,
                     block.stake_selector)

        return True

    def load_state(self) -> bool:
        # FIXME: This is odd.. not sure it should even exist
        try:
            self.pstate.prev_stake_validators_tracker = StakeValidatorsTracker.from_json(self.pstate.get_prev_stake_validators_tracker())
            self.pstate.stake_validators_tracker = StakeValidatorsTracker.from_json(self.pstate.get_stake_validators_tracker())

            block_number = self.pstate.get_state_version()
            block = Block.from_json(self.pstate.get_block(block_number))
            self.blockchain.append(block)

            return True
        except Exception:
            return False

    def get_block(self, block_idx: int) -> Optional[Block]:
        # Block chain has not been loaded yet?
        # FIXME: Ensure that the chain is already in memory

        if len(self.blockchain) > 0:
            # FIXME: The logic here is not very clear
            inmem_start_idx = self.blockchain[0].block_number
            inmem_offset = block_idx - inmem_start_idx

            if inmem_offset < 0:
                return Block.from_json(self.pstate.get_block(block_idx))

            if inmem_offset < len(self.blockchain):
                return self.blockchain[inmem_offset]

        return None

    def get_transaction(self, transaction_hash)->Optional[Transaction]:
        answer = self.pstate.get_tx_metadata(transaction_hash)
        if answer is None:
            return None
        else:
            tx, _ = answer
        return tx

    # FIXME: We need a clear database schema
    def get_blockidx_from_txhash(self, transaction_hash):
        answer = self.pstate.get_tx_metadata(transaction_hash)
        if answer is None:
            return None

        _, block_index = answer
        return block_index

    def get_last_block(self) -> Optional[Block]:
        if len(self.blockchain) == 0:
            return None

        return self.blockchain[-1]
