# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import sys
import threading
from collections import OrderedDict
from typing import Optional, Tuple
from math import ceil

import functools
from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import StringToUInt256, UInt256ToString

from qrl.core import config, BlockHeader
from qrl.core.config import DevConfig
from qrl.core.formulas import block_reward
from qrl.core.StateContainer import StateContainer
from qrl.core.StateMigration import StateMigration
from qrl.core.AddressState import AddressState
from qrl.core.VoteStats import VoteStats
from qrl.core.LastTransactions import LastTransactions
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedData import PaginatedData
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.Indexer import Indexer
from qrl.core.Block import Block
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.PoWValidator import PoWValidator
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.txs.LatticeTransaction import LatticeTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
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
    def re_org_limit(self):
        with self.lock:
            return self._state.get_re_org_limit()

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

    def get_cumulative_difficulty(self):
        with self.lock:
            last_block_metadata = BlockMetadata.get_block_metadata(self._state,
                                                                   self._last_block.headerhash)
            return last_block_metadata.cumulative_difficulty

    def get_block_by_number(self, block_number) -> Optional[Block]:
        with self.lock:
            return Block.get_block_by_number(self._state, block_number)

    def get_block_header_hash_by_number(self, block_number) -> Optional[bytes]:
        with self.lock:
            return Block.get_block_header_hash_by_number(self._state,
                                                         block_number)

    def get_block(self, header_hash: bytes) -> Optional[Block]:
        with self.lock:
            return Block.get_block(self._state, header_hash)

    def get_address_balance(self, address: bytes) -> int:
        with self.lock:
            return self.get_optimized_address_state(address).balance

    def get_address_is_used(self, address: bytes) -> bool:
        with self.lock:
            return self._state.get_address_is_used(address)

    def get_address_state(self,
                          address: bytes,
                          exclude_ots_bitfield: bool = False,
                          exclude_transaction_hashes: bool = False) -> AddressState:
        """
        Transform Optimized Address State into Older Address State format
        This should only be used by API.
        """
        optimized_address_state = self.get_optimized_address_state(address)
        ots_bitfield = []
        transaction_hashes = list()
        tokens = OrderedDict()
        slave_pks_access_type = OrderedDict()

        max_bitfield_page = ceil((2 ** optimized_address_state.height) / config.dev.ots_tracking_per_page)
        if not exclude_ots_bitfield:
            ots_bitfield = [b'\x00'] * max(1024, int(ceil((2 ** optimized_address_state.height) / 8)))
            for page in range(1, max_bitfield_page + 1):
                offset = (page - 1) * config.dev.ots_tracking_per_page
                page_data = self.get_bitfield(address, page)
                for data in page_data:
                    if offset >= len(ots_bitfield):
                        break
                    ots_bitfield[offset] = data
                    offset += 1

        if not exclude_transaction_hashes:
            max_transaction_hash_page = ceil(optimized_address_state.transaction_hash_count() / config.dev.data_per_page)

            for page in range(0, max_transaction_hash_page + 1):
                page_data = self.get_transaction_hashes(address, page * config.dev.data_per_page)
                transaction_hashes.extend(page_data)

            max_token_page = ceil(optimized_address_state.tokens_count() / config.dev.data_per_page)

            for page in range(0, max_token_page + 1):
                page_data = self.get_token_transaction_hashes(address, page * config.dev.data_per_page)
                for token_txn_hash in page_data:
                    token_balance = self.get_token(address, token_txn_hash)
                    # token_balance None is only possible when the token transaction
                    # is done by a QRL address as an owner, which has not been
                    # assigned any token balance.
                    if token_balance is None:
                        continue
                    tokens[token_txn_hash] = token_balance.balance

            max_slave_page = ceil(optimized_address_state.slaves_count() / config.dev.data_per_page)

            for page in range(0, max_slave_page + 1):
                page_data = self.get_slave_transaction_hashes(address, page * config.dev.data_per_page)
                for slave_txn_hash in page_data:
                    tx, _ = self.get_tx_metadata(slave_txn_hash)
                    for slave_pk in tx.slave_pks:
                        slave_meta_data = self.get_slave_pk_access_type(address, slave_pk)
                        slave_pks_access_type[str(slave_pk)] = slave_meta_data.access_type

        addr_state = AddressState.create(address=optimized_address_state.address,
                                         nonce=optimized_address_state.nonce,
                                         balance=optimized_address_state.balance,
                                         ots_bitfield=ots_bitfield,
                                         tokens=tokens,
                                         slave_pks_access_type=slave_pks_access_type,
                                         ots_counter=0)
        addr_state.transaction_hashes.extend(transaction_hashes)

        return addr_state

    def get_optimized_address_state(self, address: bytes) -> OptimizedAddressState:
        with self.lock:
            return OptimizedAddressState.get_optimized_address_state(self._state, address)

    def get_multi_sig_address_state(self, address: bytes) -> MultiSigAddressState:
        with self.lock:
            return MultiSigAddressState.get_multi_sig_address_state_by_address(self._state._db, address)

    def get_bitfield(self, address: bytes, page: int):
        with self.lock:
            p = PaginatedBitfield(False, self._state._db)
            return p.get_paginated_data(address, page)

    def is_slave(self, master_address: bytes, slave_pk: bytes) -> bool:
        with self.lock:
            slave_meta_data = self._state.get_slave_pk_access_type(master_address, slave_pk)
            if slave_meta_data:
                return slave_meta_data.access_type == 0
            return False

    def get_slave_pk_access_type(self, address: bytes, slave_pk: bytes) -> qrl_pb2.SlaveMetadata:
        with self.lock:
            return self._state.get_slave_pk_access_type(address, slave_pk)

    def get_transaction_hashes(self, address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_tx_hash', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(address, item_index)

    def get_multi_sig_spend_txn_hashes(self, multi_sig_address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_multi_sig_spend', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(multi_sig_address, item_index)

    def get_token_transaction_hashes(self, address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_tokens', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(address, item_index)

    def get_slave_transaction_hashes(self, address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_slaves', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(address, item_index)

    def get_lattice_pks_transaction_hashes(self, address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_lattice_pk', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(address, item_index)

    def get_multi_sig_addresses(self, address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_multisig_address', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(address, item_index)

    def get_inbox_message_transaction_hashes(self, address: bytes, item_index: int) -> list:
        p = PaginatedData(b'p_inbox_message', False, self._state._db)
        with self.lock:
            return p.get_paginated_data(address, item_index)

    def get_vote_stats(self, multi_sig_spend_txn_hash: bytes) -> VoteStats:
        with self.lock:
            return VoteStats.get_state(state=self._state, shared_key=multi_sig_spend_txn_hash)

    def get_token(self, address: bytes, token_txhash: bytes) -> qrl_pb2.TokenBalance:
        with self.lock:
            return self._state.get_token(address, token_txhash)

    def validate_all(self, tx: Transaction, check_nonce: bool) -> bool:
        with self.lock:
            addresses_set = set()
            tx.set_affected_address(addresses_set)
            state_container = self.new_state_container(addresses_set, self.height, True, None)
            if state_container is None:
                return False
            if not self.update_state_container(tx, state_container):
                return False
            return tx.validate_all(state_container, check_nonce)

    def validate_tx(self,
                    tx: Transaction,
                    addresses_state: dict,
                    addresses_bitfield: dict,
                    tokens: dict,
                    slaves: dict) -> bool:
        with self.lock:
            return self._state.validate_tx(tx, addresses_state, addresses_bitfield, tokens, slaves)

    def apply_txn(self, tx: Transaction, state_container: StateContainer) -> bool:
        with self.lock:
            return tx.apply(self._state, state_container)

    def get_tx_metadata(self, transaction_hash) -> list:
        with self.lock:
            return TransactionMetadata.get_tx_metadata(self._state, transaction_hash)

    def get_last_transactions(self):
        with self.lock:
            return LastTransactions.get_last_txs(self._state)

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
            return BlockMetadata.get_block_metadata(self._state, header_hash)

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

    def get_block_size_limit(self, block: Block, dev_config: DevConfig):
        with self.lock:
            return Block.get_block_size_limit(self._state, block, dev_config)

    def get_block_is_duplicate(self, block: Block) -> bool:
        with self.lock:
            return block.get_block(self._state, block.headerhash) is not None

    def get_config_by_block_number(self, block_number: int) -> config.DevConfig:
        dev_config = config.dev
        if block_number == 0:
            return dev_config

        with self.lock:
            while dev_config.activation_block_number >= block_number:
                dev_config_pb_data = self._state.get_dev_config_state(dev_config.prev_state_key)
                dev_config = config.DevConfig(dev_config_pb_data, True, True)
            return dev_config

    def get_seed_block(self, blockheader: BlockHeader):
        qn = Qryptonight()
        seed_height = qn.get_seed_height(blockheader.block_number)

        # If parent block belongs to main chain, then seed block will also be in the main chain
        prev_mainchain_block = self.get_block_by_number(blockheader.block_number - 1)
        if prev_mainchain_block.headerhash == blockheader.prev_headerhash:
            return self.get_block_by_number(seed_height)

        prev_block = self.get_block(blockheader.prev_headerhash)
        while prev_block.block_number > seed_height:
            prev_mainchain_block = self.get_block_by_number(prev_block.block_number)
            if prev_mainchain_block.headerhash == prev_block.headerhash:
                return self.get_block_by_number(seed_height)
            prev_block = self.get_block(prev_block.prev_headerhash)

        return prev_block

    def validate_mining_nonce(self, blockheader: BlockHeader, dev_config: config.DevConfig, enable_logging=True):
        with self.lock:
            parent_metadata = BlockMetadata.get_block_metadata(self._state, blockheader.prev_headerhash)
            parent_block = Block.get_block(self._state, blockheader.prev_headerhash)

            measurement = self.get_measurement(dev_config,
                                               blockheader.timestamp,
                                               blockheader.prev_headerhash,
                                               parent_metadata)
            diff, target = DifficultyTracker.get(
                measurement=measurement,
                parent_difficulty=parent_metadata.block_difficulty,
                dev_config=dev_config)

            mining_blob = blockheader.mining_blob(dev_config)
            qn = Qryptonight()
            seed_block = self.get_seed_block(blockheader)

            if enable_logging:
                logger.debug('-----------------START--------------------')
                logger.debug('Validate                #%s', blockheader.block_number)
                logger.debug('block.timestamp         %s', blockheader.timestamp)
                logger.debug('parent_block.timestamp  %s', parent_block.timestamp)
                logger.debug('parent_block.difficulty %s', UInt256ToString(parent_metadata.block_difficulty))
                logger.debug('diff                    %s', UInt256ToString(diff))
                logger.debug('target                  %s', bin2hstr(target))
                logger.debug('mining blob             %s', bin2hstr(mining_blob))
                logger.debug('seed_block              #%s', seed_block.block_number)
                logger.debug('seed_block hash         %s', bin2hstr(seed_block.headerhash))
                logger.debug('-------------------END--------------------')

            if not PoWValidator().verify_input(blockheader.block_number,
                                               seed_block.block_number,
                                               seed_block.headerhash,
                                               mining_blob,
                                               target):
                if enable_logging:
                    logger.warning("PoW verification failed")
                    tmp_hash = qn.hash(blockheader.block_number,
                                       seed_block.block_number,
                                       seed_block.headerhash,
                                       blockheader.mining_blob(dev_config))
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

            block = Block.get_block_by_number(self._state, end_blocknumber)
            block_headerhash = block.headerhash
            node_header_hash.headerhashes.append(block_headerhash)
            end_blocknumber -= 1

            while end_blocknumber >= start_blocknumber:
                block_metadata = BlockMetadata.get_block_metadata(self._state, block_headerhash)
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

        # Loading Current Dev Config from State
        current_state_key = self._state.get_dev_config_current_state_key()
        if current_state_key is None:
            dev_config = config.DevConfig.create(None,
                                                 config.DevConfig.get_state_key(genesis_block.headerhash),
                                                 genesis_block.headerhash,
                                                 0,
                                                 ignore_check=True)
            dev_config_pbdata = dev_config.pbdata
            self._state.put_dev_config_state(dev_config_pbdata, None)
            current_state_key = dev_config.current_state_key
            self._state.put_dev_config_current_state_key(current_state_key, None)

        dev_config_pbdata = self._state.get_dev_config_state(current_state_key)
        config.dev.update_from_pbdata(dev_config_pbdata)

        state_migration = StateMigration()
        is_state_migration_needed = self._state.is_older_state_version()
        state_version = self._state.get_state_version()
        if is_state_migration_needed:
            if state_version == 0:
                state_migration.state_migration_step_1(self._state)

        height = self._state.get_mainchain_height()

        if height == -1:
            Block.put_block(self._state, genesis_block, None)
            block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=genesis_block.headerhash,
                                                              prev_headerhash=genesis_block.prev_headerhash)
            Block.put_block_number_mapping(self._state, genesis_block.block_number, block_number_mapping, None)
            parent_difficulty = StringToUInt256(str(config.user.genesis_difficulty))

            self.current_difficulty, _ = DifficultyTracker.get(
                measurement=config.dev.block_timing_in_seconds,
                parent_difficulty=parent_difficulty,
                dev_config=config.dev)

            block_metadata = BlockMetadata.create()
            block_metadata.set_block_difficulty(self.current_difficulty)
            block_metadata.set_cumulative_difficulty(self.current_difficulty)

            BlockMetadata.put_block_metadata(self._state, genesis_block.headerhash, block_metadata, None)
            address_set = set()

            coinbase_tx = Transaction.from_pbdata(genesis_block.transactions[0])
            coinbase_tx.set_affected_address(address_set)
            state_container = self.new_state_container(address_set,
                                                       0,
                                                       True,
                                                       None)
            for genesis_balance in GenesisBlock().genesis_balance:
                bytes_addr = genesis_balance.address
                state_container.addresses_state[bytes_addr] = OptimizedAddressState.get_default(bytes_addr)
                state_container.addresses_state[bytes_addr]._data.balance = genesis_balance.balance

            for tx_idx in range(1, len(genesis_block.transactions)):
                tx = Transaction.from_pbdata(genesis_block.transactions[tx_idx])
                for addr in tx.addrs_to:
                    state_container.addresses_state[addr] = OptimizedAddressState.get_default(addr)

            if not isinstance(coinbase_tx, CoinBase):
                return False

            state_container.addresses_state[coinbase_tx.addr_to] = OptimizedAddressState.get_default(coinbase_tx.addr_to)

            if not coinbase_tx.validate_all(state_container):
                return False

            coinbase_tx.apply(self._state, state_container)

            for tx_idx in range(1, len(genesis_block.transactions)):
                tx = Transaction.from_pbdata(genesis_block.transactions[tx_idx])
                tx.apply(self._state, state_container)

            state_container.paginated_tx_hash.put_paginated_data(None)

            AddressState.put_addresses_state(self._state, state_container.addresses_state)
            state_container.paginated_bitfield.put_addresses_bitfield(None)
            TransactionMetadata.update_tx_metadata(self._state, genesis_block, None)
            self._state.update_mainchain_height(0, None)
        else:
            self._last_block = self.get_block_by_number(height)
            self.current_difficulty = BlockMetadata.get_block_metadata(self._state,
                                                                       self._last_block.headerhash).block_difficulty
            fork_state = self._state.get_fork_state()
            if fork_state:
                block = Block.get_block(self._state, fork_state.initiator_headerhash)
                self._fork_recovery(block, fork_state)

        if is_state_migration_needed:
            if state_version == 0:
                logger.warning("Please Wait... Starting State Migration From Version 0 to %s",
                               self._state.state_version)
                height = state_migration.height_from_state_version_0()
                start_block_number = self._state.get_mainchain_height() + 1
                logger.warning("Start blockheight %s", start_block_number)
                for block_number in range(start_block_number, height + 1):
                    block = state_migration.block_from_state_version_0(block_number)
                    if not self.add_block(block, check_stale=False):
                        print("System Exitting, due to migration failure")
                        sys.exit(1)
                    if block_number % 1000 == 0:
                        logger.warning("Migrated Block %s/%s", block_number, height)

                if self.height % 1000 != 0:
                    logger.warning("Migrated Block %s/%s", self.height, height)
                state_migration.state_migration_step_2(self._state)

            if state_version < 2:
                logger.warning("Please Wait... Starting State Migration From Version 1 to %s", self._state.state_version)
                height = self._state.get_mainchain_height()
                start_block_number = 1
                logger.warning("Start blockheight %s", start_block_number)
                total_block_reward = 0
                for block_number in range(start_block_number, height + 1):
                    total_block_reward += int(block_reward(block_number, config.dev))
                    if block_number % 1000 == 0:
                        logger.warning("Migrated Block %s/%s", block_number, height)

                if self.height % 1000 != 0:
                    logger.warning("Migrated Block %s/%s", self.height, height)

                logger.warning('Please Wait... While verifying State')
                total_balance = 0
                count = 0
                for address, _ in self._state._db.db:
                    address_state = None
                    if AddressState.address_is_valid(address):
                        address_state = OptimizedAddressState.get_optimized_address_state(self._state, address)
                    elif MultiSigAddressState.address_is_valid(address):
                        address_state = self.get_multi_sig_address_state(address)

                    if not address_state:
                        continue

                    count += 1
                    total_balance += address_state.balance

                    if count % 1000 == 0:
                        logger.warning("Processed Address %s", count)

                if count % 1000 != 0:
                    logger.warning("Processed Address %s", count)

                coinbase_balance = int(config.dev.coin_remaining_at_genesis * config.dev.shor_per_quanta - total_block_reward)
                total_supply = total_balance + coinbase_balance
                if total_supply != config.dev.max_coin_supply * config.dev.shor_per_quanta:
                    logger.warning('Total Supply: %s', total_supply)
                    logger.warning('Total Max Coin Supply: %s', config.dev.max_coin_supply * config.dev.shor_per_quanta)
                    raise Exception('Total supply mismatch, State Verification failed')

                a = OptimizedAddressState.get_optimized_address_state(self._state, config.dev.coinbase_address)
                a.pbdata.balance = coinbase_balance
                addresses_state = {config.dev.coinbase_address: a}
                a.put_optimized_addresses_state(self._state, addresses_state)

                a = OptimizedAddressState.get_optimized_address_state(self._state, config.dev.coinbase_address)
                if a.balance != coinbase_balance:
                    raise Exception('Unexpected Coinbase balance')
                self._state.put_state_version()
            if state_version < 3:
                # Adding extra block reward lost in block #2078158
                coinbase_addr = OptimizedAddressState.get_optimized_address_state(self._state, config.dev.coinbase_address)
                coinbase_addr.pbdata.balance += int(block_reward(2078158, config.dev))
                addresses_state = {config.dev.coinbase_address: coinbase_addr}
                coinbase_addr.put_optimized_addresses_state(self._state, addresses_state)

                self._state.put_state_version()

    def _update_chainstate(self, block: Block, batch):
        self._last_block = block
        self._update_block_number_mapping(block, batch)
        self.tx_pool.remove_tx_in_block_from_pool(block)
        self._state.update_mainchain_height(block.block_number, batch)
        self._state.update_re_org_limit(block.block_number, batch)
        TransactionMetadata.update_tx_metadata(self._state, block, batch)
        if block.block_number >= config.dev.hard_fork_heights[2]:
            banned_addr = OptimizedAddressState.get_optimized_address_state(self._state, config.dev.banned_address[0])
            if banned_addr.pbdata.balance > 0:
                banned_addr.pbdata.balance = 0
                addresses_state = {banned_addr.address: banned_addr}
                banned_addr.put_optimized_addresses_state(self._state, addresses_state)

    def _try_branch_add_block(self, block, dev_config: DevConfig, check_stale=True) -> bool:
        """
        This function returns list of bool types. The first bool represent
        if the block has been added successfully and the second bool
        represent the fork_flag, which becomes true when a block triggered
        into fork recovery.
        :param block:
        :param batch:
        :return: [Added successfully, fork_flag]
        """
        batch = self._state.batch

        if self._last_block.headerhash == block.prev_headerhash:
            if not self._apply_state_changes(block, batch):
                return False

        Block.put_block(self._state, block, batch)

        last_block_metadata = BlockMetadata.get_block_metadata(self._state, self._last_block.headerhash)
        if last_block_metadata is None:
            logger.warning("Could not find log metadata for %s", bin2hstr(self._last_block.headerhash))
            return False

        last_block_difficulty = int(UInt256ToString(last_block_metadata.cumulative_difficulty))

        new_block_metadata = self._add_block_metadata(block, dev_config, batch)
        new_block_difficulty = int(UInt256ToString(new_block_metadata.cumulative_difficulty))

        if new_block_difficulty > last_block_difficulty:
            if self._last_block.headerhash != block.prev_headerhash:
                fork_state = qrlstateinfo_pb2.ForkState(initiator_headerhash=block.headerhash)
                self._state.put_fork_state(fork_state, batch)
                self._state.write_batch(batch)
                return self._fork_recovery(block, fork_state)

            self._update_chainstate(block, batch)
            if check_stale:
                self.tx_pool.check_stale_txn(self.new_state_container,
                                             self.update_state_container,
                                             block.block_number)
            self.trigger_miner = True

        self._state.write_batch(batch)

        return True

    def _remove_block_from_mainchain(self, block: Block, latest_block_number: int, batch) -> bool:
        # Reverting Dev Config to older state, if any new config
        # was activated after addition of this block number
        if config.dev.activation_block_number == block.block_number:
            older_dev_config_pb_data = self._state.get_dev_config_state(config.dev.prev_state_key)
            self._state.put_dev_config_current_state_key(config.dev.prev_state_key, batch)
            config.dev.update_from_pbdata(older_dev_config_pb_data)

        if not self.revert_state_changes(block, batch):
            logger.warning("Fork Recovery: Revert State Changes Failed")
            return False

        self.tx_pool.add_tx_from_block_to_pool(block, latest_block_number)
        self._state.update_mainchain_height(block.block_number - 1, batch)
        TransactionMetadata.rollback_tx_metadata(self._state, block, batch)
        Block.remove_blocknumber_mapping(self._state, block.block_number, batch)

        return True

    def _get_fork_point(self, block: Block):
        tmp_block = block
        hash_path = []
        while True:
            if not block:
                raise Exception('[get_state] No Block Found %s, Initiator %s', block.headerhash, tmp_block.headerhash)

            mainchain_block = Block.get_block_by_number(self._state, block.block_number)
            if mainchain_block and mainchain_block.headerhash == block.headerhash:
                break

            if block.block_number == 0:
                raise Exception('[get_state] Alternate chain genesis is different, Initiator %s', tmp_block.headerhash)
            hash_path.append(block.headerhash)
            block = Block.get_block(self._state, block.prev_headerhash)

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
            block = Block.get_block(self._state, self._last_block.headerhash)
            mainchain_block = Block.get_block_by_number(self._state, block.block_number)

            if block is None:
                logger.warning("self.state.get_block(self.last_block.headerhash) returned None")

            if mainchain_block is None:
                logger.warning("self.get_block_by_number(block.block_number) returned None")

            if block.headerhash != mainchain_block.headerhash:
                break
            hash_path.append(self._last_block.headerhash)

            batch = self._state.batch
            if not self._remove_block_from_mainchain(self._last_block, block.block_number, batch):
                return hash_path, False

            if fork_state:
                fork_state.old_mainchain_hash_path.extend([self._last_block.headerhash])
                self._state.put_fork_state(fork_state, batch)

            self._state.write_batch(batch)

            self._last_block = Block.get_block(self._state, self._last_block.prev_headerhash)

        return hash_path, True

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
                block = Block.get_block(self._state, header_hash)

                batch = self._state.batch

                if not self._apply_state_changes(block, batch):
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
            b = Block.get_block(self._state, fork_state.old_mainchain_hash_path[-1])
            if b and b.prev_headerhash == fork_state.fork_point_headerhash:
                rollback_done = True

        success = True
        if not rollback_done:
            logger.info("Rolling back")
            old_hash_path, success = self._rollback(forked_header_hash, fork_state)
        else:
            old_hash_path = fork_state.old_mainchain_hash_path

        if not success or not self.add_chain(hash_path[-1::-1], fork_state):
            logger.warning("Fork Recovery Failed... Recovering back to old mainchain")
            # If above condition is true, then it means, the node failed to add_chain
            # Thus old chain state, must be retrieved
            self._rollback(forked_header_hash)
            self.add_chain(old_hash_path[-1::-1], fork_state)  # Restores the old chain state
            return False

        logger.info("Fork Recovery Finished")

        self.trigger_miner = True
        return True

    def _add_block(self, block, check_stale=True) -> bool:
        dev_config = self.get_config_by_block_number(block.block_number)
        self.trigger_miner = False

        block_size_limit = self.get_block_size_limit(block, dev_config)
        if block_size_limit and block.size > block_size_limit:
            logger.info('Block Size greater than threshold limit %s > %s', block.size, block_size_limit)
            return False

        return self._try_branch_add_block(block, dev_config, check_stale)

    def add_block(self, block: Block, check_stale=True) -> bool:
        with self.lock:
            if block.block_number <= self.re_org_limit:
                logger.debug('Skipping block #%s as beyond re-org limit', block.block_number)
                return False

            if self.get_block_is_duplicate(block):
                logger.warning("Duplicate Block found #%s", block.block_number)
                return False

            block_flag = self._add_block(block, check_stale=check_stale)
            if not block_flag:
                logger.warning("[ChainManager] Failed to Add Block #%s", block.block_number)
                return False

            logger.info('Added Block #%s %s', block.block_number, bin2hstr(block.headerhash))
            return True

    def _add_block_metadata(self,
                            block: Block,
                            dev_config: DevConfig,
                            batch):
        block_metadata = BlockMetadata.get_block_metadata(self._state, block.headerhash)
        if not block_metadata:
            block_metadata = BlockMetadata.create()

        parent_metadata = BlockMetadata.get_block_metadata(self._state, block.prev_headerhash)

        parent_block_difficulty = parent_metadata.block_difficulty
        parent_cumulative_difficulty = parent_metadata.cumulative_difficulty

        block_metadata.update_last_headerhashes(parent_metadata.last_N_headerhashes, block.prev_headerhash)
        measurement = self.get_measurement(dev_config, block.timestamp, block.prev_headerhash, parent_metadata)

        block_difficulty, _ = DifficultyTracker.get(
            measurement=measurement,
            parent_difficulty=parent_block_difficulty,
            dev_config=dev_config)

        block_cumulative_difficulty = StringToUInt256(str(
            int(UInt256ToString(block_difficulty)) +
            int(UInt256ToString(parent_cumulative_difficulty))))

        block_metadata.set_block_difficulty(block_difficulty)
        block_metadata.set_cumulative_difficulty(block_cumulative_difficulty)

        parent_metadata.add_child_headerhash(block.headerhash)
        BlockMetadata.put_block_metadata(self._state, block.prev_headerhash, parent_metadata, batch)
        BlockMetadata.put_block_metadata(self._state, block.headerhash, block_metadata, batch)

        return block_metadata

    def _update_block_number_mapping(self, block, batch):
        block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=block.headerhash,
                                                          prev_headerhash=block.prev_headerhash)
        Block.put_block_number_mapping(self._state, block.block_number, block_number_mapping, batch)

    @staticmethod
    def set_affected_address(block: Block) -> set:
        addresses_set = set()
        for proto_tx in block.transactions:
            tx = Transaction.from_pbdata(proto_tx)
            tx.set_affected_address(addresses_set)

        for genesis_balance in GenesisBlock().genesis_balance:
            bytes_addr = genesis_balance.address
            if bytes_addr not in addresses_set:
                addresses_set.add(bytes_addr)

        return addresses_set

    def new_state_container(self,
                            address_set: set,
                            block_number: int,
                            write_access: bool,
                            batch) -> Optional[StateContainer]:
        tokens = Indexer(b'token', self._state._db)
        slaves = Indexer(b'slave', self._state._db)
        lattice_pk = Indexer(b'lattice_pk', self._state._db)
        multi_sig_spend_txs = dict()
        votes_stats = dict()

        dev_config = self.get_config_by_block_number(block_number)

        addresses_state, success = self.get_state_mainchain(address_set)
        if not success:
            logger.warning("Failed to get state mainchain for coinbase_tx")
            return None

        return StateContainer(addresses_state,
                              tokens,
                              slaves,
                              lattice_pk,
                              multi_sig_spend_txs,
                              votes_stats,
                              block_number,
                              self._state.total_coin_supply,
                              dev_config,
                              write_access,
                              self._state._db,
                              batch)

    def update_state_container(self,
                               tx: Transaction,
                               state_container: StateContainer) -> bool:
        address_set = set()
        tx.set_affected_address(address_set)
        tokens = Indexer(b'token', self._state._db)
        slaves = Indexer(b'slave', self._state._db)
        lattice_pk = Indexer(b'lattice_pk', self._state._db)
        multi_sig_spend_txs = dict()
        votes_stats = dict()

        if not isinstance(tx, CoinBase):
            slave_addr = Transaction.get_slave(tx)
            if slave_addr is not None:
                key = (tx.addr_from, tx.PK)
                if key not in state_container.slaves.data:
                    slaves.load(key, qrl_pb2.SlaveMetadata())

        if isinstance(tx, TransferTokenTransaction):
            key = (tx.addr_from, tx.token_txhash)
            if key not in state_container.tokens.data:
                tokens.load(key, qrl_pb2.TokenBalance())

            for address in tx.addrs_to:
                key = (address, tx.token_txhash)
                if key in state_container.tokens.data:
                    continue
                tokens.load(key, qrl_pb2.TokenBalance())
        elif isinstance(tx, SlaveTransaction):
            for slave_pk in tx.slave_pks:
                key = (tx.addr_from, slave_pk)
                if key not in state_container.slaves.data:
                    slaves.load(key, qrl_pb2.SlaveMetadata())
        elif isinstance(tx, LatticeTransaction):
            key = (tx.addr_from, tx.pk1, tx.pk2, tx.pk3)
            if key not in state_container.lattice_pk.data:
                lattice_pk.load(key, qrl_pb2.LatticePKMetadata())
        # elif isinstance(tx, TokenTransaction):
        #     for initial_balance in tx.initial_balances:
        #         if (initial_balance.address, tx.txhash) not in tokens:
        #             tokens[(initial_balance.address, tx.txhash)] = 0
        elif isinstance(tx, MultiSigVote):
            if tx.shared_key not in state_container.multi_sig_spend_txs:
                tx_meta_data = TransactionMetadata.get_tx_metadata(self._state, tx.shared_key)
                if tx_meta_data is None:
                    logger.warning("[MultiSigVote] TransactionMetaData not found for the shared_key %s", tx.shared_key)
                    return False

                multi_sig_spend_tx = tx_meta_data[0]
                multi_sig_spend_txs[tx.shared_key] = multi_sig_spend_tx

                if tx.shared_key not in state_container.votes_stats:
                    votes_stats[tx.shared_key] = VoteStats.get_state(self._state,
                                                                     tx.shared_key)

                # Adding address whose address state will be affected on the execution of multi_sig txn.
                if multi_sig_spend_tx.multi_sig_address not in state_container.addresses_state:
                    address_set.add(multi_sig_spend_tx.multi_sig_address)
                for address in multi_sig_spend_tx.addrs_to:
                    if address not in state_container.addresses_state:
                        address_set.add(address)

        addresses_state, success = self.get_state_mainchain(address_set,
                                                            ignore_addresses_set=state_container.addresses_state.keys())
        if not success:
            logger.warning("get_state_mainchain failed")
            return False

        return state_container.update(addresses_state,
                                      tokens,
                                      slaves,
                                      lattice_pk,
                                      multi_sig_spend_txs,
                                      votes_stats)

    def _apply_state_changes(self, block, batch) -> bool:
        state_container = self.new_state_container(set(),
                                                   block.block_number,
                                                   True,
                                                   batch)
        if state_container is None:
            return False

        # Processing Rest of the Transaction
        for index, proto_tx in enumerate(block.transactions):
            if index > 0 and block.block_number != 2078158:
                if proto_tx.WhichOneof('transactionType') == 'coinbase':
                    logger.warning("Multiple coinbase transaction found")
                    return False

            tx = Transaction.from_pbdata(proto_tx)
            if not self.update_state_container(tx, state_container):
                return False

            if not tx.validate_all(state_container):
                return False

            tx.apply(self._state, state_container)

        # This should be done before put_addresses_state & paginated_tx_hash
        # as it make changes on the balance and add more txn hash that needed
        # to be added
        VoteStats.put_all(self._state, state_container)

        state_container.paginated_tx_hash.put_paginated_data(batch)

        state_container.paginated_lattice_pk.put_paginated_data(batch)

        state_container.paginated_multisig_address.put_paginated_data(batch)

        state_container.paginated_multi_sig_spend.put_paginated_data(batch)

        state_container.paginated_inbox_message.put_paginated_data(batch)

        # TODO: Add Key value storage to lattice pk
        state_container.tokens.put(batch)
        # This is needed to show list of tokens owned by an address on Web Wallet
        state_container.paginated_tokens_hash.put_paginated_data(batch)

        state_container.slaves.put(batch)
        # This is to retrieve the list of slaves of any particular address
        # Could be removed if not needed
        state_container.paginated_slaves_hash.put_paginated_data(batch)

        state_container.lattice_pk.put(batch)

        state_container.paginated_bitfield.put_addresses_bitfield(batch)

        AddressState.put_addresses_state(self._state, state_container.addresses_state, batch)

        return True

    def revert_state_changes(self, block, batch) -> bool:
        address_set = set()

        coinbase_tx = Transaction.from_pbdata(block.transactions[0])
        coinbase_tx.set_affected_address(address_set)
        state_container = self.new_state_container(address_set,
                                                   block.block_number,
                                                   True,
                                                   batch)
        if state_container is None:
            return False

        # Processing Rest of the Transaction
        len_transactions = len(block.transactions)
        for tx_idx in range(len_transactions - 1, 0, -1):
            tx = Transaction.from_pbdata(block.transactions[tx_idx])
            if not self.update_state_container(tx, state_container):
                logger.warning("Failed to update state_container in fork recovery")
                return False

            addr_from_pk_state = state_container.addresses_state[tx.addr_from]
            addr_from_pk = Transaction.get_slave(tx)
            if addr_from_pk:
                addr_from_pk_state = state_container.addresses_state[addr_from_pk]

            if tx.nonce != addr_from_pk_state.nonce:
                logger.warning('nonce incorrect while reverting state')
                logger.warning('subtype: %s', tx.type)
                logger.warning('%s actual: %s expected: %s', tx.addr_from, tx.nonce, addr_from_pk_state.nonce)
                return False

            if not state_container.paginated_bitfield.load_bitfield_and_ots_key_reuse(addr_from_pk_state.address, tx.ots_key):
                logger.warning('pubkey reuse not detected: invalid tx %s', bin2hstr(tx.txhash))
                logger.warning('subtype: %s', tx.type)
                return False

            if not tx.revert(self._state, state_container):
                return False

        # Reverting CoinBase Txn
        coinbase_tx.revert(self._state, state_container)

        # Invalid if slave_key doesnt exists in state
        for address_slave_pk in state_container.slaves.data:
            address, slave_pk = address_slave_pk
            access_type = self.get_slave_pk_access_type(address, slave_pk)
            if access_type is None:
                logger.warning("Failed No Access Type Found")
                return False

        # This should be done before put_addresses_state, paginated_tx_hash &
        # after vote_txn as it make changes on the balance and add more txn hash that
        # needed to be removed, as well as total weight is checked before
        # reverting the multi sig execution.
        if not VoteStats.revert_all(self._state, state_container):
            logger.warning("Failed to Revert Vote Stats")
            return False

        if not state_container.paginated_tx_hash.put_paginated_data(batch):
            logger.warning("Failed Revert Addresses Transaction Hashes")
            return False

        if not state_container.paginated_lattice_pk.put_paginated_data(batch):
            logger.warning("Failed Revert Addresses Lattice PK Hashes")
            return False

        # TODO: Put token should delete tokens address map with 0 balance
        state_container.tokens.put(batch)

        if not state_container.paginated_tokens_hash.put_paginated_data(batch):
            logger.warning("Failed Revert Tokens Hash")
            return False

        state_container.slaves.put(batch)

        if not state_container.paginated_slaves_hash.put_paginated_data(batch):
            logger.warning("Failed Revert Slaves Hash")
            return False

        state_container.lattice_pk.put(batch)

        if not state_container.paginated_multi_sig_spend.put_paginated_data(batch):
            logger.warning("Failed Revert Multi Sig Spend")
            return False

        if not state_container.paginated_inbox_message.put_paginated_data(batch):
            logger.warning("Failed Revert Inbox Message")
            return False

        if not state_container.paginated_multisig_address.put_paginated_data(batch):
            logger.warning("Failed Revert Multi Sig Addresses")
            return False

        state_container.paginated_bitfield.put_addresses_bitfield(batch)

        # All state which records page numbers, must be saved at last
        AddressState.put_addresses_state(self._state, state_container.addresses_state, batch)

        return True

    def get_state_mainchain(self, addresses_set: set, ignore_addresses_set: set = None) -> [dict, bool]:
        addresses_state = dict()
        for address in addresses_set:
            if ignore_addresses_set is not None:
                if address in ignore_addresses_set:
                    continue
            if OptimizedAddressState.address_is_valid(address) or address == config.dev.coinbase_address:
                addresses_state[address] = self.get_optimized_address_state(address)
            elif MultiSigAddressState.address_is_valid(address):
                multi_sig_address_state = MultiSigAddressState.get_multi_sig_address_state_by_address(self._state._db,
                                                                                                      address)
                addresses_state[address] = multi_sig_address_state

                # Load Address State of signatories as it needs to be processed by MultiSigSpend Txn
                # for inserting txn hash of MultiSigSpend to all signatories
                for signatory in multi_sig_address_state.signatories:
                    # Ignore signatore which are in ignore_addresses_set as their address state is already loaded
                    if ignore_addresses_set is not None:
                        if signatory in ignore_addresses_set:
                            continue
                    if OptimizedAddressState.address_is_valid(signatory):
                        addresses_state[signatory] = self.get_optimized_address_state(signatory)
                    elif MultiSigAddressState.address_is_valid(signatory):
                        addresses_state[signatory] = MultiSigAddressState.get_multi_sig_address_state_by_address(self._state._db,
                                                                                                                 signatory)
                    else:
                        return None, False
            else:
                return None, False

        return addresses_state, True

    def get_all_address_state(self) -> list:
        addresses_state = []

        try:
            for address, _ in self._state._db.db:
                if AddressState.address_is_valid(address) or address == config.dev.coinbase_address:
                    addresses_state.append(self.get_address_state(address).pbdata)
            return addresses_state
        except Exception as e:
            logger.error("Exception in get_all_address_state %s", e)

        return []

    def get_measurement(self,
                        dev_config: DevConfig,
                        block_timestamp,
                        parent_headerhash,
                        parent_metadata: BlockMetadata):
        count_headerhashes = len(parent_metadata.last_N_headerhashes)

        if count_headerhashes == 0:
            return dev_config.block_timing_in_seconds
        elif count_headerhashes == 1:
            nth_block = Block.get_block(self._state, parent_headerhash)
            count_headerhashes += 1
        else:
            nth_block = Block.get_block(self._state, parent_metadata.last_N_headerhashes[1])

        nth_block_timestamp = nth_block.timestamp
        if count_headerhashes < dev_config.N_measurement:
            nth_block_timestamp -= dev_config.block_timing_in_seconds

        return (block_timestamp - nth_block_timestamp) // count_headerhashes

    # TODO: This will be broken by stateful dev config
    @functools.lru_cache(maxsize=config.dev.block_timeseries_size + 50)
    def get_block_datapoint(self, headerhash):
        block = self.get_block(headerhash)
        if block is None:
            return None

        block_metadata = self.get_block_metadata(headerhash)
        prev_block_metadata = self.get_block_metadata(block.prev_headerhash)
        prev_block = self.get_block(block.prev_headerhash)

        data_point = qrl_pb2.BlockDataPoint()
        data_point.number = block.block_number
        data_point.header_hash = headerhash
        if prev_block is not None:
            data_point.header_hash_prev = prev_block.headerhash
        data_point.timestamp = block.timestamp
        data_point.time_last = 0
        data_point.time_movavg = 0
        data_point.difficulty = UInt256ToString(block_metadata.block_difficulty)

        if prev_block is not None:
            data_point.time_last = block.timestamp - prev_block.timestamp
            if prev_block.block_number == 0:
                data_point.time_last = config.dev.block_timing_in_seconds

            movavg = self.get_measurement(config.dev,
                                          block.timestamp,
                                          block.prev_headerhash,
                                          prev_block_metadata)
            data_point.time_movavg = movavg

            try:
                # FIXME: need to consider average difficulty here
                data_point.hash_power = int(data_point.difficulty) * (config.dev.block_timing_in_seconds / movavg)
            except ZeroDivisionError:
                data_point.hash_power = 0

        return data_point

    def get_unused_ots_index2(self, address, start_ots_index=0):
        return self.get_unused_ots_index(addresses_bitfield=dict(),
                                         addresses_state=dict(),
                                         address=address,
                                         paginated_bitfield=PaginatedBitfield(False, self._state._db),
                                         start_ots_index=start_ots_index)

    def get_unused_ots_index(self,
                             addresses_bitfield: dict,
                             addresses_state: dict,
                             address,
                             paginated_bitfield: PaginatedBitfield,
                             start_ots_index=0):
        """
        Finds the unused ots index above the given start_ots_index.
        """
        if address not in addresses_state:
            addresses_state[address] = self.get_optimized_address_state(address)

        address_state = addresses_state[address]

        ots_key_count = (2 ** address_state.height)
        max_page = ceil(ots_key_count / config.dev.ots_tracking_per_page)
        if address_state.ots_bitfield_used_page == max_page:
            return None

        page = max(address_state.ots_bitfield_used_page, start_ots_index // config.dev.ots_tracking_per_page) + 1

        for i in range((page - 1) * config.dev.ots_tracking_per_page // 8, ots_key_count // 8):
            page = (i // config.dev.ots_tracking_per_page) + 1
            key = paginated_bitfield.generate_bitfield_key(address, page)
            if key not in addresses_bitfield:
                addresses_bitfield[key] = paginated_bitfield.get_paginated_data(address, page)

            ots_bitfield = addresses_bitfield[key]
            index = i % config.dev.ots_tracking_per_page
            if ots_bitfield[index][0] < 255:
                offset = 8 * index + (page - 1) * config.dev.ots_tracking_per_page
                bitfield = bytearray(ots_bitfield[index])
                for relative in range(0, 8):
                    if ((bitfield[0] >> relative) & 1) != 1:
                        if offset + relative >= start_ots_index:
                            return offset + relative

        return None
