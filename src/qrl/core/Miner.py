# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
import threading
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr, hstr2bin
from pyqryptonight.pyqryptonight import UInt256ToString

from qrl.core.config import DevConfig
from qrl.core.miners.qryptonight7.CNv1Miner import CNv1Miner
from qrl.core.miners.qrandomx.QRXMiner import QRandomXMiner
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.Block import Block
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.TransactionPool import TransactionPool
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.Qryptonight import Qryptonight


class Miner:
    def __init__(self,
                 chain_manager,
                 pre_block_logic,
                 mining_address: bytes,
                 mining_thread_count):
        self.lock = threading.RLock()

        self.qryptonight_7_miner = CNv1Miner(pre_block_logic,
                                             mining_address,
                                             mining_thread_count,
                                             self.lock)

        self.qrandomx_miner = QRandomXMiner(chain_manager,
                                            pre_block_logic,
                                            mining_address,
                                            mining_thread_count,
                                            self.lock)
        self._qn = Qryptonight()
        self._chain_manager = chain_manager
        self._pre_block_logic = pre_block_logic
        self._mining_block = None
        self._current_difficulty = None
        self._current_target = None
        self._measurement = None

        self._current_miner = self.qrandomx_miner

    def isRunning(self):
        return self._current_miner.isRunning

    def get_miner(self, height, dev_config: DevConfig):
        if height < dev_config.hard_fork_heights[0]:
            self._current_miner = self.qryptonight_7_miner
            return self.qryptonight_7_miner
        else:
            self._current_miner = self.qrandomx_miner
            return self.qrandomx_miner

    def solutionAvailable(self):
        return self._current_miner.solutionAvailable()

    def prepare_next_unmined_block_template(self,
                                            mining_address,
                                            tx_pool,
                                            parent_block: Block,
                                            parent_difficulty,
                                            dev_config: DevConfig):
        miner = self.get_miner(parent_block.block_number + 1, dev_config)
        try:
            logger.debug('Miner-Try - prepare_next_unmined_block_template')
            with self.lock:
                logger.debug('Miner-Locked - prepare_next_unmined_block_template')

                logger.debug('Miner-TryCancel - prepare_next_unmined_block_template')
                miner.cancel()
                logger.debug('Miner-Cancel - prepare_next_unmined_block_template')

                self._mining_block = self.create_block(last_block=parent_block,
                                                       mining_nonce=0,
                                                       tx_pool=tx_pool,
                                                       miner_address=mining_address)

                parent_metadata = self._chain_manager.get_block_metadata(parent_block.headerhash)
                self._measurement = self._chain_manager.get_measurement(dev_config,
                                                                        self._mining_block.timestamp,
                                                                        self._mining_block.prev_headerhash,
                                                                        parent_metadata)

                self._current_difficulty, self._current_target = DifficultyTracker.get(
                    measurement=self._measurement,
                    parent_difficulty=parent_difficulty,
                    dev_config=dev_config)

        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

    def start_mining(self,
                     parent_block: Block,
                     parent_difficulty,
                     dev_config: DevConfig):
        logger.debug('!!! Mine #{} | {} ({}) | {} -> {} | {} '.format(
            self._mining_block.block_number,
            self._measurement, self._mining_block.timestamp - parent_block.timestamp,
            UInt256ToString(parent_difficulty), UInt256ToString(self._current_difficulty),
            bin2hstr(bytearray(self._current_target))
        ))
        logger.debug('!!! Mine #{} | blob: {}'.format(
            self._mining_block.block_number,
            bin2hstr(bytearray(self._mining_block.mining_blob(dev_config)))
        ))
        miner = self.get_miner(parent_block.block_number + 1, dev_config)
        miner.start_mining(self._mining_block, self._current_target, dev_config)

    def create_block(self,
                     last_block,
                     mining_nonce,
                     tx_pool: TransactionPool,
                     miner_address) -> Optional[Block]:
        seed_block = self._chain_manager.get_block_by_number(self._qn.get_seed_height(last_block.block_number + 1))
        dev_config = self._chain_manager.get_config_by_block_number(block_number=last_block.block_number + 1)

        dummy_block = Block.create(dev_config=dev_config,
                                   block_number=last_block.block_number + 1,
                                   prev_headerhash=last_block.headerhash,
                                   prev_timestamp=last_block.timestamp,
                                   transactions=[],
                                   miner_address=miner_address,
                                   seed_height=seed_block.block_number,
                                   seed_hash=seed_block.headerhash)
        dummy_block.set_nonces(dev_config, mining_nonce, 0)

        t_pool2 = tx_pool.transactions

        block_size = dummy_block.size
        block_size_limit = self._chain_manager.get_block_size_limit(last_block, dev_config)

        transactions = []
        state_container = self._chain_manager.new_state_container(set(),
                                                                  last_block.block_number,
                                                                  True,
                                                                  None)
        for tx_set in t_pool2:
            tx = tx_set[1].transaction

            # Skip Transactions for later, which doesn't fit into block
            if block_size + tx.size + dev_config.tx_extra_overhead > block_size_limit:
                continue

            if not self._chain_manager.update_state_container(tx, state_container):
                logger.error("[create_block] Error updating state_container")
                return None

            if not tx.validate_all(state_container, check_nonce=False):
                if not state_container.revert_update():
                    return None
                tx_pool.remove_tx_from_pool(tx)
                continue
            if not self._chain_manager.apply_txn(tx, state_container):
                logger.error("[create_block] Failed to apply txn")
                if not state_container.revert_update():
                    return None
                continue

            addr_from_pk_state = state_container.addresses_state[tx.addr_from]
            addr_from_pk = Transaction.get_slave(tx)
            if addr_from_pk:
                addr_from_pk_state = state_container.addresses_state[addr_from_pk]

            tx._data.nonce = addr_from_pk_state.nonce
            block_size += tx.size + dev_config.tx_extra_overhead
            transactions.append(tx)

        block = Block.create(dev_config=dev_config,
                             block_number=last_block.block_number + 1,
                             prev_headerhash=last_block.headerhash,
                             prev_timestamp=last_block.timestamp,
                             transactions=transactions,
                             miner_address=miner_address,
                             seed_height=seed_block.block_number,
                             seed_hash=seed_block.headerhash)

        return block

    def get_block_to_mine(self,
                          wallet_address,
                          tx_pool,
                          last_block,
                          last_block_difficulty) -> list:
        dev_config = self._chain_manager.get_config_by_block_number(last_block.block_number + 1)
        try:
            mining_address = bytes(hstr2bin(wallet_address[1:].decode()))

            if not OptimizedAddressState.address_is_valid(mining_address):
                raise ValueError("[get_block_to_mine] Invalid Wallet Address %s", wallet_address)
        except Exception as e:
            raise ValueError("Error while decoding wallet address %s", e)

        if self._mining_block:
            if last_block.headerhash == self._mining_block.prev_headerhash:
                if self._mining_block.transactions[0].coinbase.addr_to == mining_address:
                    return [bin2hstr(self._mining_block.mining_blob(dev_config)),
                            int(bin2hstr(self._current_difficulty), 16)]
                else:
                    self._mining_block.update_mining_address(dev_config, mining_address)  # Updates only Miner Address

        self.prepare_next_unmined_block_template(mining_address,
                                                 tx_pool,
                                                 last_block,
                                                 last_block_difficulty,
                                                 dev_config=dev_config)

        return [bin2hstr(self._mining_block.mining_blob(dev_config)),
                int(bin2hstr(self._current_difficulty), 16)]

    def submit_mined_block(self, blob: bytes) -> bool:
        dev_config = self._chain_manager.get_config_by_block_number(self._mining_block.block_number - 1)
        if not self._mining_block.verify_blob(blob, dev_config):
            return False

        blockheader = copy.deepcopy(self._mining_block.blockheader)
        blockheader.set_mining_nonce_from_blob(blob, dev_config)

        dev_config = self._chain_manager.get_config_by_block_number(blockheader.block_number)

        if not self._chain_manager.validate_mining_nonce(blockheader, dev_config):
            return False

        self._mining_block.set_nonces(dev_config,
                                      blockheader.mining_nonce,
                                      blockheader.extra_nonce)
        cloned_block = copy.deepcopy(self._mining_block)
        return self._pre_block_logic(cloned_block)

    def cancel(self):
        self.qryptonight_7_miner.cancel()
        self.qrandomx_miner.cancel()
