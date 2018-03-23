# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional

import functools
from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import StringToUInt256, UInt256ToString, PoWHelper

from qrl.core import config
from qrl.core.PoWValidator import PoWValidator
from qrl.crypto.Qryptonight import Qryptonight
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Transaction import Transaction, CoinBase
from qrl.core.TransactionPool import TransactionPool
from qrl.core.misc import logger
from qrl.generated import qrl_pb2


class ChainManager:
    def __init__(self, state):
        self.state = state
        self.tx_pool = TransactionPool()  # TODO: Move to some pool manager
        self.last_block = Block.from_json(GenesisBlock().to_json())
        self.current_difficulty = StringToUInt256(str(config.dev.genesis_difficulty))

        self.trigger_miner = False

    @property
    def height(self):
        return self.last_block.block_number

    def get_last_block(self) -> Block:
        return self.last_block

    def get_cumulative_difficulty(self):
        last_block_metadata = self.state.get_block_metadata(self.last_block.headerhash)
        return last_block_metadata.cumulative_difficulty

    def load(self, genesis_block):
        height = self.state.get_mainchain_height()

        if height == -1:
            self.state.put_block(genesis_block, None)
            block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=genesis_block.headerhash,
                                                              prev_headerhash=genesis_block.prev_headerhash)

            self.state.put_block_number_mapping(genesis_block.block_number, block_number_mapping, None)
            parent_difficulty = StringToUInt256(str(config.dev.genesis_difficulty))

            self.current_difficulty, _ = DifficultyTracker.get(
                measurement=config.dev.mining_setpoint_blocktime,
                parent_difficulty=parent_difficulty)

            block_metadata = BlockMetadata.create()

            block_metadata.set_orphan(False)
            block_metadata.set_block_difficulty(self.current_difficulty)
            block_metadata.set_cumulative_difficulty(self.current_difficulty)

            self.state.put_block_metadata(genesis_block.headerhash, block_metadata, None)
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

            if not coinbase_tx.validate_extended():
                return False

            coinbase_tx.apply_on_state(addresses_state)

            for tx_idx in range(1, len(genesis_block.transactions)):
                tx = Transaction.from_pbdata(genesis_block.transactions[tx_idx])
                tx.apply_on_state(addresses_state)

            self.state.state_objects.update_current_state(addresses_state)
            self.state.state_objects.push(genesis_block.headerhash)
            self.state.update_tx_metadata(genesis_block, None)
        else:
            self.last_block = self.get_block_by_number(height)
            self.current_difficulty = self.state.get_block_metadata(self.last_block.headerhash).block_difficulty

    def validate_mining_nonce(self, block, enable_logging=False):
        parent_metadata = self.state.get_block_metadata(block.prev_headerhash)
        parent_block = self.state.get_block(block.prev_headerhash)

        measurement = self.state.get_measurement(block.timestamp, block.prev_headerhash, parent_metadata)
        diff, target = DifficultyTracker.get(
            measurement=measurement,
            parent_difficulty=parent_metadata.block_difficulty)

        if enable_logging:
            logger.debug('-----------------START--------------------')
            logger.debug('Validate #%s', block.block_number)
            logger.debug('block.timestamp %s', block.timestamp)
            logger.debug('parent_block.timestamp %s', parent_block.timestamp)
            logger.debug('parent_block.difficulty %s', UInt256ToString(parent_metadata.block_difficulty))
            logger.debug('diff : %s | target : %s', UInt256ToString(diff), target)
            logger.debug('-------------------END--------------------')

        if not self.verify_input_cached(block.mining_blob, target):
            if enable_logging:
                logger.warning("PoW verification failed")
                qn = Qryptonight()
                tmp_hash = qn.hash(block.mining_blob)
                logger.warning("{}".format(tmp_hash))
                logger.debug('%s', block.to_json())
            return False

        return True

    @functools.lru_cache(maxsize=5)
    def verify_input_cached(self, mining_blob, target):
        return PoWHelper.verifyInput(mining_blob, target)

    def validate_block(self, block, address_txn) -> bool:
        len_transactions = len(block.transactions)

        if len_transactions < 1:
            return False

        coinbase_tx = Transaction.from_pbdata(block.transactions[0])

        if not isinstance(coinbase_tx, CoinBase):
            return False

        if not coinbase_tx.validate_extended():
            return False

        if not PoWValidator().validate_mining_nonce(self.state, block.blockheader):
            return False

        coinbase_tx.apply_on_state(address_txn)

        # TODO: check block reward must be equal to coinbase amount

        for tx_idx in range(1, len_transactions):
            tx = Transaction.from_pbdata(block.transactions[tx_idx])

            if isinstance(tx, CoinBase):
                return False

            if not tx.validate():  # TODO: Move this validation, before adding txn to pool
                return False

            addr_from_pk_state = address_txn[tx.addr_from]
            addr_from_pk = Transaction.get_slave(tx)
            if addr_from_pk:
                addr_from_pk_state = address_txn[addr_from_pk]

            if not tx.validate_extended(address_txn[tx.addr_from], addr_from_pk_state):
                return False

            expected_nonce = addr_from_pk_state.nonce + 1

            if tx.nonce != expected_nonce:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.type)
                logger.warning('%s actual: %s expected: %s', tx.addr_from, tx.nonce, expected_nonce)
                return False

            if addr_from_pk_state.ots_key_reuse(tx.ots_key):
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.type)
                return False

            tx.apply_on_state(address_txn)

        return True

    def _pre_check(self, block, ignore_duplicate):
        if block.block_number < 1:
            return False

        if not block.validate():
            return False

        if (not ignore_duplicate) and self.state.get_block(block.headerhash):  # Duplicate block check
            logger.info('Duplicate block %s %s', block.block_number, bin2hstr(block.headerhash))
            return False

        return True

    def _try_orphan_add_block(self, block, batch):
        prev_block_metadata = self.state.get_block_metadata(block.prev_headerhash)

        self.trigger_miner = False

        if prev_block_metadata is None or prev_block_metadata.is_orphan:
            self.state.put_block(block, batch)
            self.add_block_metadata(block.headerhash, block.timestamp, block.prev_headerhash, batch)
            return True

        return False

    def _try_branch_add_block(self, block, batch=None) -> bool:
        parent_block = self.state.get_block(block.prev_headerhash)
        if not block.validate_parent_child_relation(parent_block):
            logger.warning('Failed to validate blocks parent child relation')
            return False

        address_set = self.state.prepare_address_list(block)  # Prepare list for current block
        if self.last_block.headerhash == block.prev_headerhash:
            address_txn = self.state.get_state_mainchain(address_set)
        else:
            address_txn = self.state.get_state(block.prev_headerhash, address_set)

        if self.validate_block(block, address_txn):
            self.state.put_block(block, None)
            self.add_block_metadata(block.headerhash, block.timestamp, block.prev_headerhash, None)

            last_block_metadata = self.state.get_block_metadata(self.last_block.headerhash)
            new_block_metadata = self.state.get_block_metadata(block.headerhash)
            last_block_difficulty = int(UInt256ToString(last_block_metadata.cumulative_difficulty))
            new_block_difficulty = int(UInt256ToString(new_block_metadata.cumulative_difficulty))

            self.trigger_miner = False
            if new_block_difficulty > last_block_difficulty:
                if self.last_block.headerhash != block.prev_headerhash:
                    self.rollback(block)
                    return True

                self.state.update_mainchain_state(address_txn, block.block_number, block.headerhash)
                self.last_block = block
                self._update_mainchain(block, batch)
                self.tx_pool.remove_tx_in_block_from_pool(block)
                self.state.update_mainchain_height(block.block_number, batch)
                self.state.update_tx_metadata(block, batch)

                self.trigger_miner = True

            return True

        return False

    def rollback(self, block):
        hash_path = []
        while True:
            if self.state.state_objects.contains(block.headerhash):
                break
            hash_path.append(block.headerhash)
            new_block = self.state.get_block(block.prev_headerhash)
            if not new_block:
                logger.warning('No block found %s', block.prev_headerhash)
                break
            block = new_block
            if block.block_number == 0:
                del hash_path[-1]  # Skip replaying Genesis Block
                break

        block = self.state.get_block(hash_path[-1])
        self.state.state_objects.destroy_fork_states(block.block_number, block.headerhash)
        self.state.state_objects.destroy_current_state(None)

        for header_hash in hash_path[-1::-1]:
            block = self.state.get_block(header_hash)
            address_set = self.state.prepare_address_list(block)  # Prepare list for current block
            addresses_state = self.state.get_state_mainchain(address_set)

            for tx_idx in range(0, len(block.transactions)):
                tx = Transaction.from_pbdata(block.transactions[tx_idx])
                tx.apply_on_state(addresses_state)

            self.state.update_mainchain_state(addresses_state, block.block_number, block.headerhash)
            self.last_block = block
            self._update_mainchain(block, None)
            self.tx_pool.remove_tx_in_block_from_pool(block)
            self.state.update_mainchain_height(block.block_number, None)
            self.state.update_tx_metadata(block, None)

        self.trigger_miner = True

    def _add_block(self, block, ignore_duplicate=False, batch=None):
        block_size_limit = self.state.get_block_size_limit(block)
        if block_size_limit and block.size > block_size_limit:
            logger.info('Block Size greater than threshold limit %s > %s', block.size, block_size_limit)
            return False

        if not self._pre_check(block, ignore_duplicate):
            logger.debug('Failed pre_check')
            return False

        if self._try_orphan_add_block(block, batch):
            return True

        if self._try_branch_add_block(block, batch):
            return True

        return False

    def add_block(self, block: Block) -> bool:
        if block.block_number < self.height - config.dev.reorg_limit:
            logger.debug('Skipping block #%s as beyond re-org limit', block.block_number)
            return False

        batch = self.state.get_batch()
        if self._add_block(block, batch=batch):
            self.state.write_batch(batch)
            self.update_child_metadata(block.headerhash)
            return True

        return False

    def update_child_metadata(self, headerhash):
        block_metadata = self.state.get_block_metadata(headerhash)

        childs = list(block_metadata.child_headerhashes)

        while childs:
            child_headerhash = childs.pop(0)
            block = self.state.get_block(child_headerhash)
            if not block:
                continue
            if not self._add_block(block, True):
                self._prune([block.headerhash], None)
                continue
            block_metadata = self.state.get_block_metadata(child_headerhash)
            childs += block_metadata.child_headerhashes

    def _prune(self, childs, batch):
        while childs:
            child_headerhash = childs.pop(0)

            block_metadata = self.state.get_block_metadata(child_headerhash)
            childs += block_metadata.child_headerhashes

            self.state.delete(bin2hstr(child_headerhash).encode(), batch)
            self.state.delete(b'metadata_' + bin2hstr(child_headerhash).encode(), batch)

    def add_block_metadata(self,
                           headerhash,
                           block_timestamp,
                           parent_headerhash,
                           batch):
        block_metadata = self.state.get_block_metadata(headerhash)
        if not block_metadata:
            block_metadata = BlockMetadata.create()

        parent_metadata = self.state.get_block_metadata(parent_headerhash)
        block_difficulty = (0,) * 32  # 32 bytes to represent 256 bit of 0
        block_cumulative_difficulty = (0,) * 32  # 32 bytes to represent 256 bit of 0
        if not parent_metadata:
            parent_metadata = BlockMetadata.create()
        else:
            parent_block = self.state.get_block(parent_headerhash)
            if parent_block:
                parent_block_difficulty = parent_metadata.block_difficulty
                parent_cumulative_difficulty = parent_metadata.cumulative_difficulty

                if not parent_metadata.is_orphan:
                    block_metadata.update_last_headerhashes(parent_metadata.last_N_headerhashes, parent_headerhash)
                    measurement = self.state.get_measurement(block_timestamp, parent_headerhash, parent_metadata)

                    block_difficulty, _ = DifficultyTracker.get(
                        measurement=measurement,
                        parent_difficulty=parent_block_difficulty)

                    block_cumulative_difficulty = StringToUInt256(str(
                        int(UInt256ToString(block_difficulty)) +
                        int(UInt256ToString(parent_cumulative_difficulty))))

        block_metadata.set_orphan(parent_metadata.is_orphan)
        block_metadata.set_block_difficulty(block_difficulty)
        block_metadata.set_cumulative_difficulty(block_cumulative_difficulty)

        parent_metadata.add_child_headerhash(headerhash)
        self.state.put_block_metadata(parent_headerhash, parent_metadata, batch)
        self.state.put_block_metadata(headerhash, block_metadata, batch)

        # Call once to populate the cache
        self.state.get_block_datapoint(headerhash)

    def _update_mainchain(self, block, batch):
        block_number_mapping = None
        while block_number_mapping is None or block.headerhash != block_number_mapping.headerhash:
            block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=block.headerhash,
                                                              prev_headerhash=block.prev_headerhash)
            self.state.put_block_number_mapping(block.block_number, block_number_mapping, batch)
            block = self.state.get_block(block.prev_headerhash)
            block_number_mapping = self.state.get_block_number_mapping(block.block_number)

    def get_block_by_number(self, block_number) -> Optional[Block]:
        return self.state.get_block_by_number(block_number)

    def get_state(self, headerhash):
        return self.state.get_state(headerhash, set())

    def get_address(self, address):
        return self.state.get_address(address)

    def get_transaction(self, transaction_hash) -> list:
        for tx_set in self.tx_pool.transactions:
            tx = tx_set[1]
            if tx.txhash == transaction_hash:
                return [tx, None]

        return self.state.get_tx_metadata(transaction_hash)

    def get_headerhashes(self, start_blocknumber):
        start_blocknumber = max(0, start_blocknumber)
        end_blocknumber = min(self.last_block.block_number,
                              start_blocknumber + 2 * config.dev.reorg_limit)

        total_expected_headerhash = end_blocknumber - start_blocknumber + 1

        node_header_hash = qrl_pb2.NodeHeaderHash()
        node_header_hash.block_number = start_blocknumber

        block = self.state.get_block_by_number(end_blocknumber)
        block_headerhash = block.headerhash
        node_header_hash.headerhashes.append(block_headerhash)
        end_blocknumber -= 1

        while end_blocknumber >= start_blocknumber:
            block_metadata = self.state.get_block_metadata(block_headerhash)
            for headerhash in block_metadata.last_N_headerhashes[-1::-1]:
                node_header_hash.headerhashes.append(headerhash)
            end_blocknumber -= len(block_metadata.last_N_headerhashes)
            if len(block_metadata.last_N_headerhashes) == 0:
                break
            block_headerhash = block_metadata.last_N_headerhashes[0]

        node_header_hash.headerhashes[:] = node_header_hash.headerhashes[-1::-1]
        del node_header_hash.headerhashes[:len(node_header_hash.headerhashes) - total_expected_headerhash]

        return node_header_hash

    def add_ephemeral_message(self, encrypted_ephemeral: EncryptedEphemeralMessage):
        self.state.update_ephemeral(encrypted_ephemeral)
