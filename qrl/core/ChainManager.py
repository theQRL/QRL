# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional
from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import PoWHelper, StringToUInt256, UInt256ToString

from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.AddressState import AddressState
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.Miner import Miner
from qrl.core.misc import logger, ntp
from qrl.core import config
from qrl.core.Block import Block
from qrl.core.Transaction import Transaction
from qrl.core.TransactionPool import TransactionPool
from qrl.generated import qrl_pb2


class ChainManager:
    def __init__(self, state):
        self.state = state
        self.tx_pool = TransactionPool()  # TODO: Move to some pool manager
        self.last_block = GenesisBlock()
        self.current_difficulty = StringToUInt256(str(config.dev.genesis_difficulty))
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
        parent_difficulty = StringToUInt256(str(config.dev.genesis_difficulty))

        self.current_difficulty, self.current_target = Miner.calc_difficulty(genesis_block.timestamp,
                                                                             genesis_block.timestamp-60,
                                                                             parent_difficulty)
        block_metadata = BlockMetadata.create()

        block_metadata.set_orphan(False)
        block_metadata.set_block_difficulty(self.current_difficulty)
        block_metadata.set_cumulative_difficulty(self.current_difficulty)

        self.state.put_block_metadata(genesis_block.headerhash, block_metadata, None)

    def validate_block(self, block, address_txn, state) -> bool:
        len_transactions = len(block.transactions)

        if len_transactions < 1:
            return False

        coinbase_tx = Transaction.from_pbdata(block.transactions[0])
        coinbase_tx.validate()

        parent_metadata = self.state.get_block_metadata(block.prev_headerhash)

        input_bytes = StringToUInt256(str(block.mining_nonce))[-4:] + tuple(block.mining_hash)
        ph = PoWHelper()
        target = ph.getBoundary(parent_metadata.block_difficulty)
        if not self.miner.custom_qminer.verifyInput(input_bytes, target):
            logger.warning("PoW verification failed")
            return False

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
            self.add_block_metadata(block.headerhash, block.timestamp, block.prev_headerhash, batch)
            return False

        if self.validate_block(block, address_txn, self.state):
            self.state.update_state(address_txn)
            self.state.put_block(block, batch)
            self.add_block_metadata(block.headerhash, block.timestamp, block.prev_headerhash, batch)
            if block.block_number > self.last_block.block_number:
                self.last_block = block
                self.update_mainchain(block, batch)
                self.mine_next(block, address_txn)
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

    def add_block_metadata(self, headerhash, block_timestamp, parent_headerhash, batch):
        parent_metadata = self.state.get_block_metadata(parent_headerhash)
        block_difficulty = (0,) * 32  # 32 bytes to represent 256 bit of 0
        block_cumulative_difficulty = (0,) * 32  # 32 bytes to represent 256 bit of 0
        if not parent_metadata:
            parent_metadata = BlockMetadata.create()
        else:
            parent_block = self.state.get_block(parent_headerhash)
            parent_block_difficulty = parent_metadata.block_difficulty
            parent_cumulative_difficulty = parent_metadata.cumulative_difficulty
            block_difficulty, _ = Miner.calc_difficulty(block_timestamp, parent_block.timestamp, parent_block_difficulty)
            block_cumulative_difficulty = StringToUInt256(str(
                                                          int(UInt256ToString(block_difficulty)) +
                                                          int(UInt256ToString(parent_cumulative_difficulty))))

        block_metadata = self.state.get_block_metadata(headerhash)
        if not block_metadata:
            block_metadata = BlockMetadata.create()

        block_metadata.set_orphan(parent_metadata.is_orphan)
        block_metadata.set_block_difficulty(block_difficulty)
        block_metadata.set_cumulative_difficulty(block_cumulative_difficulty)
        parent_metadata.add_child_headerhash(headerhash)
        self.state.put_block_metadata(parent_headerhash, parent_metadata, batch)
        self.state.put_block_metadata(headerhash, block_metadata, batch)

    def update_mainchain(self, block, batch):
        current_time = int(ntp.getTime())
        self.current_difficulty, self.current_target = Miner.calc_difficulty(current_time,
                                                                             block.timestamp,
                                                                             self.current_difficulty)
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

    def mine_next(self, parent_block, address_txn):
        logger.info('Mining Block #%s', self.last_block.block_number+1)
        self.miner.start_mining(address_txn, self.tx_pool, parent_block, self.current_target)
