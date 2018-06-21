# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
import threading
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr, hstr2bin
from pyqryptonight.pyqryptonight import Qryptominer, UInt256ToString, SOLUTION

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.TransactionPool import TransactionPool
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


class Miner(Qryptominer):
    def __init__(self,
                 pre_block_logic,
                 mining_address: bytes,
                 chain_manager,
                 mining_thread_count,
                 add_unprocessed_txn_fn):
        super().__init__()
        self.pre_block_logic = pre_block_logic  # FIXME: Circular dependency with node.py

        self._mining_block = None
        self._current_difficulty = None
        self._current_target = None
        self._measurement = None  # Required only for logging

        self._mining_address = mining_address
        self._reward_address = None
        self._chain_manager = chain_manager
        self._add_unprocessed_txn_fn = add_unprocessed_txn_fn
        self._mining_thread_count = mining_thread_count
        self._dummy_xmss = None
        self.setForcedSleep(config.user.mining_pause)

        self.lock = threading.RLock()

    def prepare_next_unmined_block_template(self, mining_address, tx_pool, parent_block: Block, parent_difficulty):
        try:
            logger.debug('Miner-Try - prepare_next_unmined_block_template')
            with self.lock:
                logger.debug('Miner-Locked - prepare_next_unmined_block_template')

                logger.debug('Miner-TryCancel - prepare_next_unmined_block_template')
                self.cancel()
                logger.debug('Miner-Cancel - prepare_next_unmined_block_template')

                self._mining_block = self.create_block(last_block=parent_block,
                                                       mining_nonce=0,
                                                       tx_pool=tx_pool,
                                                       miner_address=mining_address)

                parent_metadata = self._chain_manager.get_block_metadata(parent_block.headerhash)
                self._measurement = self._chain_manager.get_measurement(self._mining_block.timestamp,
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
            logger.debug('start_mining - TRY LOCK')
            with self.lock:
                logger.debug('start_mining - LOCKED')
                self.cancel()

                mining_blob = self._mining_block.mining_blob
                nonce_offset = self._mining_block.mining_nonce_offset

                logger.debug('!!! Mine #{} | {} ({}) | {} -> {} | {} '.format(
                    self._mining_block.block_number,
                    self._measurement, self._mining_block.timestamp - parent_block.timestamp,
                    UInt256ToString(parent_difficulty), UInt256ToString(self._current_difficulty),
                    bin2hstr(bytearray(self._current_target))
                ))
                logger.debug('!!! Mine #{} | blob: {}'.format(
                    self._mining_block.block_number,
                    bin2hstr(bytearray(mining_blob))
                ))

                work_seq_id = self.start(input=mining_blob,
                                         nonceOffset=nonce_offset,
                                         target=self._current_target,
                                         thread_count=self._mining_thread_count)

                logger.debug("MINING START [{}]".format(work_seq_id))

        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

        logger.debug('start_mining - UNLOCKED')

    def handleEvent(self, event):
        # NOTE: This function usually runs in the context of a C++ thread
        if event.type == SOLUTION:
            logger.debug('handleEvent - TRY LOCK')
            if not self.lock.acquire(blocking=False):
                logger.debug('handleEvent - SKIP')
                return False

            try:
                logger.debug('handleEvent - LOCKED')

                logger.debug('Solution Found %s', event.nonce)
                logger.info('Hash Rate: %s H/s', self.hashRate())
                cloned_block = copy.deepcopy(self._mining_block)
                cloned_block.set_nonces(event.nonce, 0)
                logger.debug("Blob           %s", cloned_block)
                logger.info('Block #%s nonce: %s', cloned_block.block_number, event.nonce)
                self.pre_block_logic(cloned_block)
            except Exception as e:
                logger.warning("Exception in solutionEvent")
                logger.exception(e)
            finally:
                logger.debug('handleEvent - UNLOCK')
                self.lock.release()

        return True

    def create_block(self,
                     last_block,
                     mining_nonce,
                     tx_pool: TransactionPool,
                     miner_address) -> Optional[Block]:
        dummy_block = Block.create(block_number=last_block.block_number + 1,
                                   prev_headerhash=last_block.headerhash,
                                   prev_timestamp=last_block.timestamp,
                                   transactions=[],
                                   miner_address=miner_address)
        dummy_block.set_nonces(mining_nonce, 0)

        t_pool2 = tx_pool.transactions

        addresses_set = set()
        for tx_set in t_pool2:
            tx = tx_set[1].transaction
            tx.set_affected_address(addresses_set)

        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self._chain_manager.get_address_state(address)

        block_size = dummy_block.size
        block_size_limit = self._chain_manager.get_block_size_limit(last_block)

        transactions = []
        for tx_set in t_pool2:
            tx = tx_set[1].transaction
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

            tx.apply_state_changes(addresses_state)

            tx._data.nonce = addr_from_pk_state.nonce
            block_size += tx.size + config.dev.tx_extra_overhead
            transactions.append(tx)

        block = Block.create(block_number=last_block.block_number + 1,
                             prev_headerhash=last_block.headerhash,
                             prev_timestamp=last_block.timestamp,
                             transactions=transactions,
                             miner_address=miner_address)

        return block

    def get_block_to_mine(self, wallet_address, tx_pool, last_block, last_block_difficulty) -> list:
        try:
            mining_address = bytes(hstr2bin(wallet_address[1:].decode()))

            if not AddressState.address_is_valid(mining_address):
                raise ValueError("[get_block_to_mine] Invalid Wallet Address %s", wallet_address)
        except Exception as e:
            raise ValueError("Error while decoding wallet address %s", e)

        if self._mining_block:
            if last_block.headerhash == self._mining_block.prev_headerhash:
                if self._mining_block.transactions[0].coinbase.addr_to == mining_address:
                    return [bin2hstr(self._mining_block.mining_blob),
                            int(bin2hstr(self._current_difficulty), 16)]
                else:
                    self._mining_block.update_mining_address(mining_address)  # Updates only Miner Address

        self.prepare_next_unmined_block_template(mining_address, tx_pool, last_block, last_block_difficulty)

        return [bin2hstr(self._mining_block.mining_blob),
                int(bin2hstr(self._current_difficulty), 16)]

    def submit_mined_block(self, blob: bytes) -> bool:
        if not self._mining_block.verify_blob(blob):
            return False

        blockheader = copy.deepcopy(self._mining_block.blockheader)
        blockheader.set_mining_nonce_from_blob(blob)

        if not self._chain_manager.validate_mining_nonce(blockheader):
            return False

        self._mining_block.set_nonces(blockheader.mining_nonce, blockheader.extra_nonce)
        cloned_block = copy.deepcopy(self._mining_block)
        self.pre_block_logic(cloned_block)
        return True
