# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional
from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import PoWHelper, StringToUInt256

from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.AddressState import AddressState
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.misc import logger, ntp
from qrl.core.Block import Block
from qrl.core.Transaction import Transaction
from qrl.core.TransactionPool import TransactionPool
from qrl.generated import qrl_pb2


class ChainManager:
    def __init__(self, state):
        self.state = state
        self.tx_pool = TransactionPool()  # TODO: Move to some pool manager
        self.last_block = GenesisBlock()
        self.current_difficulty = StringToUInt256("5000")
        self.current_target = None
        self.miner = None

    @property
    def height(self):
        return self.last_block.block_number

    def set_miner(self, miner):
        self.miner = miner

    def get_last_block(self) -> Block:
        return self.last_block

    def load(self, genesis_block):
        self.state.put_block(genesis_block, None)
        block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=genesis_block.headerhash,
                                                          prev_headerhash=genesis_block.prev_headerhash)
        self.state.put_block_number_mapping(genesis_block.block_number, block_number_mapping, None)
        self.current_difficulty = StringToUInt256("5000")
        ph = PoWHelper()
        self.current_target = ph.getBoundary(self.current_difficulty)

    def validate_block(self, block, address_txn, state) -> bool:
        len_transactions = len(block.transactions)

        if len_transactions < 1:
            return False

        coinbase_tx = Transaction.from_pbdata(block.transactions[0])
        coinbase_tx.validate()

        if coinbase_tx.subtype != qrl_pb2.Transaction.COINBASE:
            return False

        if not coinbase_tx.validate():
            return False

        address_txn[coinbase_tx.txto] = AddressState.get_default(coinbase_tx.txto)
        coinbase_tx.apply_on_state(address_txn)

        if not coinbase_tx.validate_extended(address_txn[coinbase_tx.txfrom], block.blockheader):
            return False

        # TODO: check block reward must be equal to coinbase amount

        for tx_idx in range(1, len_transactions):
            tx = Transaction.from_pbdata(block.transactions[tx_idx])

            if tx.subtype == qrl_pb2.Transaction.COINBASE:
                return False

            if not tx.validate():   # TODO: Move this validation, before adding txn to pool
                return False

            if tx.addr_from not in address_txn:
                address_txn[tx.txfrom] = AddressState.get_default(tx.addr_from)

            if tx.subtype in (qrl_pb2.Transaction.TRANSFER, qrl_pb2.Transaction.TRANSFERTOKEN):
                if tx.txto not in address_txn:
                    address_txn[tx.txto] = AddressState.get_default(tx.txto)

            if tx.subtype == qrl_pb2.Transaction.TOKEN:
                for initial_balance in tx.initial_balances:
                    if initial_balance not in address_txn:
                        address_txn[initial_balance.address] = AddressState.get_default(initial_balance.address)

            if not tx.validate_extended(address_txn[tx.txfrom], self.tx_pool.transaction_pool):
                return False

            expected_nonce = address_txn[tx.txfrom].nonce + 1

            if tx.nonce != expected_nonce:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.subtype)
                logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, expected_nonce)
                return False

            if tx.ots_key_reuse(address_txn[tx.txfrom], tx.ots_key):
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.subtype)
                return False

            tx.apply_on_state(address_txn)

        return True

    def _add_block(self, block, ignore_duplicate=False, batch=None) -> bool:
        if block.block_number < 1:
            return False

        if (not ignore_duplicate) and self.state.get_block(block.headerhash):  # Duplicate block check
            return False

        address_txn = self.state.get_state(block.prev_headerhash)

        if not address_txn:
            self.state.put_block(block, batch)
            self.add_block_metadata(block.headerhash, block.prev_headerhash, 0, batch)
            return False

        if self.validate_block(block, address_txn, self.state):
            self.state.update_state(address_txn)
            self.state.put_block(block, batch)
            self.add_block_metadata(block.headerhash, block.prev_headerhash, 0, batch)
            if block.block_number > self.last_block.block_number:
                self.last_block = block
                self.update_mainchain(block, batch)
                self.mine_next()
            # TODO: Also add total_difficulty check
            return True
        return False

    def add_block(self, block: Block) -> bool:
        batch = None
        if self._add_block(block, batch=batch):
            self.update_child_metadata(block.headerhash, batch)
            return True
        return False

    def update_child_metadata(self, headerhash, batch):
        block_metadata = self.state.get_block_metadata(headerhash)

        childs = list(block_metadata.child_headerhashes)

        while childs:
            child_headerhash = childs.pop(0)
            block = self.state.get_block(child_headerhash)
            if not block:
                continue
            if not self._add_block(block, True, batch):
                self._prune([block.headerhash], batch=batch)
                continue
            block_metadata = self.state.get_block_metadata(child_headerhash)
            childs += block_metadata.child_headerhashes

    def _prune(self, childs, batch):
        while childs:
            child_headerhash = childs.pop(0)

            block_metadata = self.state.get_block_metadata(child_headerhash)
            childs += block_metadata.child_headerhashes

            batch.Delete(bin2hstr(child_headerhash).encode())
            batch.Delete(b'metadata_' + bin2hstr(child_headerhash).encode())

    def add_block_metadata(self, headerhash, parent_headerhash, block_difficulty, batch):
        parent_metadata = self.state.get_block_metadata(parent_headerhash)
        if not parent_metadata:
            parent_metadata = BlockMetadata.create()

        cumulative_difficulty = parent_metadata.cumulative_difficulty + block_difficulty

        block_metadata = self.state.get_block_metadata(headerhash)
        if not block_metadata:
            block_metadata = BlockMetadata.create()

        block_metadata.set_orphan(parent_metadata.is_orphan)
        block_metadata.set_cumulative_difficulty(cumulative_difficulty)
        parent_metadata.add_child_headerhash(headerhash)

        self.state.put_block_metadata(parent_headerhash, parent_metadata, batch)
        self.state.put_block_metadata(headerhash, block_metadata, batch)

    def update_mainchain(self, block, batch):
        ph = PoWHelper()
        current_time = int(ntp.getTime())
        self.current_difficulty = ph.getDifficulty(timestamp=current_time,
                                                   parent_timestamp=block.timestamp,
                                                   parent_difficulty=self.current_difficulty)
        self.current_target = ph.getBoundary(self.current_difficulty)
        block_number_mapping = None
        while block_number_mapping is None or block.headerhash != block_number_mapping.headerhash:
            block_number_mapping = qrl_pb2.BlockNumberMapping(headerhash=block.headerhash,
                                                              prev_headerhash=block.prev_headerhash)
            self.state.put_block_number_mapping(block.block_number, block_number_mapping, batch)
            block = self.state.get_block(block.prev_headerhash)
            block_number_mapping = self.state.get_block_number_mapping(block.block_number)

    def get_block_by_headerhash(self, headerhash) -> Optional[Block]:
        return self.state.get_block_by_headerhash(headerhash)

    def get_block_by_number(self, block_number) -> Optional[Block]:
        return self.state.get_block_by_number(block_number)

    def get_state(self, headerhash):
        return self.state.get_state(headerhash)

    def get_mining_data(self):
        input_bytes = [0x03, 0x05, 0x07, 0x09, 0x19]
        return input_bytes, 0, self.current_target

    def mine_next(self):
        logger.info('Mining Block #%s', self.last_block.block_number+1)
        input_bytes, nonce_offset, current_target = self.get_mining_data()
        self.miner.start_mining(input_bytes, nonce_offset, current_target)
