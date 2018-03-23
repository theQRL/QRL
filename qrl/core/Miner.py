# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import Qryptominer, StringToUInt256, UInt256ToString

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.PoWValidator import PoWValidator
from qrl.core.State import State
from qrl.core.TransactionPool import TransactionPool
from qrl.core.Transaction import Transaction
from qrl.core.misc import logger


class Miner(Qryptominer):
    def __init__(self,
                 pre_block_logic,
                 mining_credit_wallet: bytes,
                 state: State,
                 mining_thread_count,
                 add_unprocessed_txn_fn):
        super().__init__()
        self.pre_block_logic = pre_block_logic  # FIXME: Circular dependency with node.py

        self._mining_block = None
        self._current_difficulty = None
        self._current_target = None
        self._measurement = None  # Required only for logging

        self._mining_credit_wallet = mining_credit_wallet
        self._reward_address = None
        self.state = state
        self._add_unprocessed_txn_fn = add_unprocessed_txn_fn
        self._mining_thread_count = mining_thread_count
        self._dummy_xmss = None

    def prepare_next_unmined_block_template(self, tx_pool, parent_block: Block, parent_difficulty):
        try:
            self.cancel()
            self._mining_block = self.create_block(last_block=parent_block,
                                                   mining_nonce=0,
                                                   tx_pool=tx_pool,
                                                   miner_address=self._mining_credit_wallet)

            parent_metadata = self.state.get_block_metadata(parent_block.headerhash)
            self._measurement = self.state.get_measurement(self._mining_block.timestamp,
                                                           self._mining_block.prev_headerhash,
                                                           parent_metadata)

            self._current_difficulty, self._current_target = DifficultyTracker.get(
                measurement=self._measurement,
                parent_difficulty=parent_difficulty)

        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

    def start_mining(self,
                     parent_block: Block,
                     parent_difficulty):
        try:
            self.cancel()

            mining_blob = self._mining_block.mining_blob
            nonce_offset = self._mining_block.mining_nonce_offset

            logger.debug('!!! Mine #{} | {} ({}) | {} -> {} | {}'.format(
                self._mining_block.block_number,
                self._measurement, self._mining_block.timestamp - parent_block.timestamp,
                UInt256ToString(parent_difficulty), UInt256ToString(self._current_difficulty),
                self._current_target
            ))

            self.start(input=mining_blob,
                       nonceOffset=nonce_offset,
                       target=self._current_target,
                       thread_count=self._mining_thread_count)
        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

    def solutionEvent(self, nonce):
        # NOTE: This function usually runs in the context of a C++ thread
        try:
            logger.debug('Solution Found %s', nonce)
            self._mining_block.set_mining_nonce(nonce)
            logger.info('Block #%s nonce: %s', self._mining_block.block_number, StringToUInt256(str(nonce))[-4:])
            logger.info('Hash Rate: %s H/s', self.hashRate())
            cloned_block = copy.deepcopy(self._mining_block)
            self.pre_block_logic(cloned_block)
        except Exception as e:
            logger.warning("Exception in solutionEvent")
            logger.exception(e)

    def create_block(self,
                     last_block,
                     mining_nonce,
                     tx_pool: TransactionPool,
                     miner_address) -> Optional[Block]:
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        dummy_block = Block.create(block_number=last_block.block_number + 1,
                                   prevblock_headerhash=last_block.headerhash,
                                   transactions=[],
                                   miner_address=miner_address)
        dummy_block.set_mining_nonce(mining_nonce)

        t_pool2 = tx_pool.transactions

        addresses_set = set()
        for tx_set in t_pool2:
            tx = tx_set[1]
            tx.set_effected_address(addresses_set)

        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self.state.get_address(address)

        block_size = dummy_block.size
        block_size_limit = self.state.get_block_size_limit(last_block)

        transactions = []
        for tx_set in t_pool2:
            tx = tx_set[1]
            # Skip Transactions for later, which doesn't fit into block
            if block_size + tx.size + config.dev.tx_extra_overhead > block_size_limit:
                continue

            addr_from_pk_state = addresses_state[tx.addr_from]
            addr_from_pk = Transaction.get_slave(tx)
            if addr_from_pk:
                addr_from_pk_state = addresses_state[addr_from_pk]

            if not tx.validate_extended(addresses_state[tx.addr_from], addr_from_pk_state):
                logger.warning('Txn validation failed for tx in tx_pool')
                tx_pool.remove_tx_from_pool(tx)
                continue

            tx.apply_on_state(addresses_state)

            tx._data.nonce = addr_from_pk_state.nonce
            block_size += tx.size + config.dev.tx_extra_overhead
            transactions.append(tx)

        block = Block.create(block_number=last_block.block_number + 1,
                             prevblock_headerhash=last_block.headerhash,
                             transactions=transactions,
                             miner_address=miner_address)

        return block

    def get_block_to_mine(self, wallet_address) -> list:
        # TODO: use wallet_address to track the share
        if not self._mining_block:
            return []

        return [bin2hstr(self._mining_block.mining_blob),
                int(bin2hstr(self._current_difficulty), 16)]

    def submit_mined_block(self, blob) -> bool:
        if not self._mining_block.verify_blob(blob):
            return False

        blockheader = copy.deepcopy(self._mining_block.blockheader)
        blockheader.set_mining_nonce_from_blob(blob)

        if not PoWValidator().validate_mining_nonce(self.state, blockheader=blockheader):
            return False

        self._mining_block.set_mining_nonce(blockheader.mining_nonce)
        cloned_block = copy.deepcopy(self._mining_block)
        self.pre_block_logic(cloned_block)
        return True
