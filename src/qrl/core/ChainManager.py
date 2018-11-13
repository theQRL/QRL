# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading
from typing import Optional, Tuple

from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import StringToUInt256, UInt256ToString

from qrl.core import config, BlockHeader
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.PoWValidator import PoWValidator
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.TransactionPool import TransactionPool
from qrl.core.misc import logger
from qrl.crypto.Qryptonight import Qryptonight
from qrl.generated import qrl_pb2, qrlstateinfo_pb2


class ChainManager:
    def __init__(self, state):
        self._state = state
        self.tx_pool = TransactionPool(None)
        self._last_block = Block.deserialize(GenesisBlock().serialize())
        self.current_difficulty = StringToUInt256(str(config.user.genesis_difficulty))

        self.trigger_miner = False
        self.lock = threading.RLock()

    @property
    def height(self):
        with self.lock:
            if not self._last_block:
                return -1
            return self._last_block.block_number

    @property
    def last_block(self) -> Block:
        with self.lock:
            return self._last_block

    @property
    def total_coin_supply(self):
        with self.lock:
            return self._state.total_coin_supply

    def get_block_datapoint(self, headerhash):
        with self.lock:
            return self._state.get_block_datapoint(headerhash)

    def get_cumulative_difficulty(self):
        with self.lock:
            last_block_metadata = self._state.get_block_metadata(self._last_block.headerhash)
            return last_block_metadata.cumulative_difficulty

    def get_block_by_number(self, block_number) -> Optional[Block]:
        with self.lock:
            return self._state.get_block_by_number(block_number)

    def get_block_header_hash_by_number(self, block_number) -> Optional[bytes]:
        with self.lock:
            return self._state.get_block_header_hash_by_number(block_number)

    def get_block(self, header_hash: bytes) -> Optional[Block]:
        with self.lock:
            return self._state.get_block(header_hash)

    def get_address_balance(self, address: bytes) -> int:
        with self.lock:
            return self._state.get_address_balance(address)

    def get_address_is_used(self, address: bytes) -> bool:
        with self.lock:
            return self._state.get_address_is_used(address)

    def get_address_state(self, address: bytes) -> AddressState:
        with self.lock:
            return self._state.get_address_state(address)

    def get_all_address_state(self):
        with self.lock:
            return self._state.get_all_address_state()

    def get_tx_metadata(self, transaction_hash) -> list:
        with self.lock:
            return self._state.get_tx_metadata(transaction_hash)

    def get_last_transactions(self):
        with self.lock:
            return self._state.get_last_txs()

    def get_unconfirmed_transaction(self, transaction_hash) -> list:
        with self.lock:
            for tx_set in self.tx_pool.transactions:
                tx = tx_set[1].transaction
                if tx.txhash == transaction_hash:
                    return [tx, tx_set[1].timestamp]
            if transaction_hash in self.tx_pool.pending_tx_pool_hash:
                for tx_set in self.tx_pool.pending_tx_pool:
                    tx = tx_set[1].transaction
                    if tx.txhash == transaction_hash:
                        return [tx, tx_set[1].timestamp]

            return []

    def get_block_metadata(self, header_hash: bytes) -> Optional[BlockMetadata]:
        with self.lock:
            return self._state.get_block_metadata(header_hash)

    def get_blockheader_and_metadata(self, block_number=0) -> Tuple:
        with self.lock:
            block_number = block_number or self.height  # if both are non-zero, then block_number takes priority

            result = (None, None)
            block = self.get_block_by_number(block_number)
            if block:
                blockheader = block.blockheader
                blockmetadata = self.get_block_metadata(blockheader.headerhash)
                result = (blockheader, blockmetadata)

            return result

    def get_block_to_mine(self, miner, wallet_address) -> list:
        with miner.lock:  # Trying to acquire miner.lock to make sure pre_block_logic is not running
            with self.lock:
                last_block = self.last_block
                last_block_metadata = self.get_block_metadata(last_block.headerhash)
                return miner.get_block_to_mine(wallet_address,
                                               self.tx_pool,
                                               last_block,
                                               last_block_metadata.block_difficulty)

    def get_measurement(self, block_timestamp, parent_headerhash, parent_metadata: BlockMetadata):
        with self.lock:
            return self._state.get_measurement(block_timestamp, parent_headerhash, parent_metadata)

    def get_block_size_limit(self, block: Block):
        with self.lock:
            return self._state.get_block_size_limit(block)

    def get_block_is_duplicate(self, block: Block) -> bool:
        with self.lock:
            return self._state.get_block(block.headerhash) is not None

    def validate_mining_nonce(self, blockheader: BlockHeader, enable_logging=True):
        with self.lock:
            parent_metadata = self.get_block_metadata(blockheader.prev_headerhash)
            parent_block = self._state.get_block(blockheader.prev_headerhash)

            measurement = self.get_measurement(blockheader.timestamp, blockheader.prev_headerhash, parent_metadata)
            diff, target = DifficultyTracker.get(
                measurement=measurement,
                parent_difficulty=parent_metadata.block_difficulty)

            if enable_logging:
                logger.debug('-----------------START--------------------')
                logger.debug('Validate                #%s', blockheader.block_number)
                logger.debug('block.timestamp         %s', blockheader.timestamp)
                logger.debug('parent_block.timestamp  %s', parent_block.timestamp)
                logger.debug('parent_block.difficulty %s', UInt256ToString(parent_metadata.block_difficulty))
                logger.debug('diff                    %s', UInt256ToString(diff))
                logger.debug('target                  %s', bin2hstr(target))
                logger.debug('-------------------END--------------------')

            if not PoWValidator().verify_input(blockheader.mining_blob, target):
                if enable_logging:
                    logger.warning("PoW verification failed")
                    qn = Qryptonight()
                    tmp_hash = qn.hash(blockheader.mining_blob)
                    logger.warning("{}".format(bin2hstr(tmp_hash)))
                    logger.debug('%s', blockheader.to_json())
                return False

            return True

    def get_headerhashes(self, start_blocknumber):
        with self.lock:
            start_blocknumber = max(0, start_blocknumber)
            end_blocknumber = min(self._last_block.block_number,
                                  start_blocknumber + 2 * config.dev.reorg_limit)

            total_expected_headerhash = end_blocknumber - start_blocknumber + 1

            node_header_hash = qrl_pb2.NodeHeaderHash()
            node_header_hash.block_number = start_blocknumber

            block = self._state.get_block_by_number(end_blocknumber)
            block_headerhash = block.headerhash
            node_header_hash.headerhashes.append(block_headerhash)
            end_blocknumber -= 1

            while end_blocknumber >= start_blocknumber:
                block_metadata = self._state.get_block_metadata(block_headerhash)
                for headerhash in block_metadata.last_N_headerhashes[-1::-1]:
                    node_header_hash.headerhashes.append(headerhash)
                end_blocknumber -= len(block_metadata.last_N_headerhashes)
                if len(block_metadata.last_N_headerhashes) == 0:
                    break
                block_headerhash = block_metadata.last_N_headerhashes[0]

            node_header_hash.headerhashes[:] = node_header_hash.headerhashes[-1::-1]
            del node_header_hash.headerhashes[:len(node_header_hash.headerhashes) - total_expected_headerhash]

            return node_header_hash

    def set_broadcast_tx(self, broadcast_tx):
        with self.lock:
            self.tx_pool.set_broadcast_tx(broadcast_tx)

    def load(self, genesis_block):
        # load() has the following tasks:
        # Write Genesis Block into State immediately
        # Register block_number <-> blockhash mapping
        # Calculate difficulty Metadata for Genesis Block
        # Generate AddressStates from Genesis Block balances
        # Apply Genesis Block's transactions to the state
        # Detect if we are forked from genesis block and if so initiate recovery.
        height = self._state.get_mainchain_height()

        if height == -1:
            self._state.put_block(genesis_block, None)
            block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=genesis_block.headerhash,
                                                              prev_headerhash=genesis_block.prev_headerhash)

            self._state.put_block_number_mapping(genesis_block.block_number, block_number_mapping, None)
            parent_difficulty = StringToUInt256(str(config.user.genesis_difficulty))

            self.current_difficulty, _ = DifficultyTracker.get(
                measurement=config.dev.mining_setpoint_blocktime,
                parent_difficulty=parent_difficulty)

            block_metadata = BlockMetadata.create()
            block_metadata.set_block_difficulty(self.current_difficulty)
            block_metadata.set_cumulative_difficulty(self.current_difficulty)

            self._state.put_block_metadata(genesis_block.headerhash, block_metadata, None)
            addresses_state = dict()
            for genesis_balance in GenesisBlock().genesis_balance:
                bytes_addr = genesis_balance.address
                addresses_state[bytes_addr] = AddressState.get_default(bytes_addr)
                addresses_state[bytes_addr]._data.balance = genesis_balance.balance

            for tx_idx in range(1, len(genesis_block.transactions)):
                tx = Transaction.from_pbdata(genesis_block.transactions[tx_idx])
                for addr in tx.addrs_to:
                    addresses_state[addr] = AddressState.get_default(addr)

            coinbase_tx = Transaction.from_pbdata(genesis_block.transactions[0])

            if not isinstance(coinbase_tx, CoinBase):
                return False

            addresses_state[coinbase_tx.addr_to] = AddressState.get_default(coinbase_tx.addr_to)

            if not coinbase_tx.validate_extended(genesis_block.block_number):
                return False

            coinbase_tx.apply_state_changes(addresses_state)

            for tx_idx in range(1, len(genesis_block.transactions)):
                tx = Transaction.from_pbdata(genesis_block.transactions[tx_idx])
                tx.apply_state_changes(addresses_state)

            self._state.put_addresses_state(addresses_state)
            self._state.update_tx_metadata(genesis_block, None)
            self._state.update_mainchain_height(0, None)
        else:
            self._last_block = self.get_block_by_number(height)
            self.current_difficulty = self._state.get_block_metadata(self._last_block.headerhash).block_difficulty
            fork_state = self._state.get_fork_state()
            if fork_state:
                block = self._state.get_block(fork_state.initiator_headerhash)
                self._fork_recovery(block, fork_state)

    def _apply_block(self, block: Block, batch) -> bool:
        address_set = self._state.prepare_address_list(block)  # Prepare list for current block
        addresses_state = self._state.get_state_mainchain(address_set)
        if not block.apply_state_changes(addresses_state):
            return False
        self._state.put_addresses_state(addresses_state, batch)
        return True

    def _update_chainstate(self, block: Block, batch):
        self._last_block = block
        self._update_block_number_mapping(block, batch)
        self.tx_pool.remove_tx_in_block_from_pool(block)
        self._state.update_mainchain_height(block.block_number, batch)
        self._state.update_tx_metadata(block, batch)

    def _try_branch_add_block(self, block, batch, check_stale=True) -> (bool, bool):
        """
        This function returns list of bool types. The first bool represent
        if the block has been added successfully and the second bool
        represent the fork_flag, which becomes true when a block triggered
        into fork recovery.
        :param block:
        :param batch:
        :return: [Added successfully, fork_flag]
        """
        if self._last_block.headerhash == block.prev_headerhash:
            if not self._apply_block(block, batch):
                return False, False

        self._state.put_block(block, batch)

        last_block_metadata = self._state.get_block_metadata(self._last_block.headerhash)
        if last_block_metadata is None:
            logger.warning("Could not find log metadata for %s", bin2hstr(self._last_block.headerhash))
            return False, False

        last_block_difficulty = int(UInt256ToString(last_block_metadata.cumulative_difficulty))

        new_block_metadata = self._add_block_metadata(block.headerhash, block.timestamp, block.prev_headerhash, batch)
        new_block_difficulty = int(UInt256ToString(new_block_metadata.cumulative_difficulty))

        if new_block_difficulty > last_block_difficulty:
            if self._last_block.headerhash != block.prev_headerhash:
                fork_state = qrlstateinfo_pb2.ForkState(initiator_headerhash=block.headerhash)
                self._state.put_fork_state(fork_state, batch)
                self._state.write_batch(batch)
                return self._fork_recovery(block, fork_state), True

            self._update_chainstate(block, batch)
            if check_stale:
                self.tx_pool.check_stale_txn(self._state, block.block_number)
            self.trigger_miner = True

        return True, False

    def _remove_block_from_mainchain(self, block: Block, latest_block_number: int, batch):
        addresses_set = self._state.prepare_address_list(block)
        addresses_state = self._state.get_state_mainchain(addresses_set)
        for tx_idx in range(len(block.transactions) - 1, -1, -1):
            tx = Transaction.from_pbdata(block.transactions[tx_idx])
            tx.revert_state_changes(addresses_state, self)

        self.tx_pool.add_tx_from_block_to_pool(block, latest_block_number)
        self._state.update_mainchain_height(block.block_number - 1, batch)
        self._state.rollback_tx_metadata(block, batch)
        self._state.remove_blocknumber_mapping(block.block_number, batch)
        self._state.put_addresses_state(addresses_state, batch)

    def _get_fork_point(self, block: Block):
        tmp_block = block
        hash_path = []
        while True:
            if not block:
                raise Exception('[get_state] No Block Found %s, Initiator %s', block.headerhash, tmp_block.headerhash)
            mainchain_block = self.get_block_by_number(block.block_number)
            if mainchain_block and mainchain_block.headerhash == block.headerhash:
                break
            if block.block_number == 0:
                raise Exception('[get_state] Alternate chain genesis is different, Initiator %s', tmp_block.headerhash)
            hash_path.append(block.headerhash)
            block = self._state.get_block(block.prev_headerhash)

        return block.headerhash, hash_path

    def _rollback(self, forked_header_hash: bytes, fork_state: qrlstateinfo_pb2.ForkState = None):
        """
        Rollback from last block to the block just before the forked_header_hash
        :param forked_header_hash:
        :param fork_state:
        :return:
        """
        hash_path = []
        while self._last_block.headerhash != forked_header_hash:
            block = self._state.get_block(self._last_block.headerhash)
            mainchain_block = self._state.get_block_by_number(block.block_number)

            if block is None:
                logger.warning("self.state.get_block(self.last_block.headerhash) returned None")

            if mainchain_block is None:
                logger.warning("self.get_block_by_number(block.block_number) returned None")

            if block.headerhash != mainchain_block.headerhash:
                break
            hash_path.append(self._last_block.headerhash)

            batch = self._state.batch
            self._remove_block_from_mainchain(self._last_block, block.block_number, batch)

            if fork_state:
                fork_state.old_mainchain_hash_path.extend([self._last_block.headerhash])
                self._state.put_fork_state(fork_state, batch)

            self._state.write_batch(batch)

            self._last_block = self._state.get_block(self._last_block.prev_headerhash)

        return hash_path

    def add_chain(self, hash_path: list, fork_state: qrlstateinfo_pb2.ForkState) -> bool:
        """
        Add series of blocks whose headerhash mentioned into hash_path
        :param hash_path:
        :param fork_state:
        :param batch:
        :return:
        """
        with self.lock:
            start = 0
            try:
                start = hash_path.index(self._last_block.headerhash) + 1
            except ValueError:
                # Following condition can only be true if the fork recovery was interrupted last time
                if self._last_block.headerhash in fork_state.old_mainchain_hash_path:
                    return False

            for i in range(start, len(hash_path)):
                header_hash = hash_path[i]
                block = self._state.get_block(header_hash)

                batch = self._state.batch

                if not self._apply_block(block, batch):
                    return False

                self._update_chainstate(block, batch)

                logger.debug('Apply block #%d - [batch %d | %s]', block.block_number, i, hash_path[i])
                self._state.write_batch(batch)

            self._state.delete_fork_state()

            return True

    def _fork_recovery(self, block: Block, fork_state: qrlstateinfo_pb2.ForkState) -> bool:
        logger.info("Triggered Fork Recovery")
        # This condition only becomes true, when fork recovery was interrupted
        if fork_state.fork_point_headerhash:
            logger.info("Recovering from last fork recovery interruption")
            forked_header_hash, hash_path = fork_state.fork_point_headerhash, fork_state.new_mainchain_hash_path
        else:
            forked_header_hash, hash_path = self._get_fork_point(block)
            fork_state.fork_point_headerhash = forked_header_hash
            fork_state.new_mainchain_hash_path.extend(hash_path)
            self._state.put_fork_state(fork_state)

        rollback_done = False
        if fork_state.old_mainchain_hash_path:
            b = self._state.get_block(fork_state.old_mainchain_hash_path[-1])
            if b and b.prev_headerhash == fork_state.fork_point_headerhash:
                rollback_done = True

        if not rollback_done:
            logger.info("Rolling back")
            old_hash_path = self._rollback(forked_header_hash, fork_state)
        else:
            old_hash_path = fork_state.old_mainchain_hash_path

        if not self.add_chain(hash_path[-1::-1], fork_state):
            logger.warning("Fork Recovery Failed... Recovering back to old mainchain")
            # If above condition is true, then it means, the node failed to add_chain
            # Thus old chain state, must be retrieved
            self._rollback(forked_header_hash)
            self.add_chain(old_hash_path[-1::-1], fork_state)  # Restores the old chain state
            return False

        logger.info("Fork Recovery Finished")

        self.trigger_miner = True
        return True

    def _add_block(self, block, batch=None, check_stale=True) -> (bool, bool):
        self.trigger_miner = False

        block_size_limit = self.get_block_size_limit(block)
        if block_size_limit and block.size > block_size_limit:
            logger.info('Block Size greater than threshold limit %s > %s', block.size, block_size_limit)
            return False, False

        return self._try_branch_add_block(block, batch, check_stale)

    def add_block(self, block: Block, check_stale=True) -> bool:
        with self.lock:
            if block.block_number < self.height - config.dev.reorg_limit:
                logger.debug('Skipping block #%s as beyond re-org limit', block.block_number)
                return False

            if self.get_block_is_duplicate(block):
                return False

            batch = self._state.batch
            block_flag, fork_flag = self._add_block(block, batch=batch, check_stale=check_stale)
            if block_flag:
                if not fork_flag:
                    self._state.write_batch(batch)
                logger.info('Added Block #%s %s', block.block_number, bin2hstr(block.headerhash))
                return True

            return False

    def _add_block_metadata(self,
                            headerhash,
                            block_timestamp,
                            parent_headerhash,
                            batch):
        block_metadata = self._state.get_block_metadata(headerhash)
        if not block_metadata:
            block_metadata = BlockMetadata.create()

        parent_metadata = self._state.get_block_metadata(parent_headerhash)

        parent_block_difficulty = parent_metadata.block_difficulty
        parent_cumulative_difficulty = parent_metadata.cumulative_difficulty

        block_metadata.update_last_headerhashes(parent_metadata.last_N_headerhashes, parent_headerhash)
        measurement = self._state.get_measurement(block_timestamp, parent_headerhash, parent_metadata)

        block_difficulty, _ = DifficultyTracker.get(
            measurement=measurement,
            parent_difficulty=parent_block_difficulty)

        block_cumulative_difficulty = StringToUInt256(str(
            int(UInt256ToString(block_difficulty)) +
            int(UInt256ToString(parent_cumulative_difficulty))))

        block_metadata.set_block_difficulty(block_difficulty)
        block_metadata.set_cumulative_difficulty(block_cumulative_difficulty)

        parent_metadata.add_child_headerhash(headerhash)
        self._state.put_block_metadata(parent_headerhash, parent_metadata, batch)
        self._state.put_block_metadata(headerhash, block_metadata, batch)

        return block_metadata

    def _update_block_number_mapping(self, block, batch):
        block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=block.headerhash,
                                                          prev_headerhash=block.prev_headerhash)
        self._state.put_block_number_mapping(block.block_number, block_number_mapping, batch)
