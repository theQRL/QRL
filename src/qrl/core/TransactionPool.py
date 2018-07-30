# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import heapq
from typing import List
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.txs.Transaction import Transaction, OTSType
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.TransactionInfo import TransactionInfo
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.generated import qrl_pb2


class TransactionPool:
    # FIXME: Remove tx pool from all method names
    def __init__(self, broadcast_tx, chain_manager):
        self.chain_manager = chain_manager
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = set()
        self.transaction_pool = []  # FIXME: Everyone is touching this
        self.broadcast_tx = broadcast_tx

    @property
    def manifest(self):
        txhashes = [t[1].transaction.txhash for t in self.transaction_pool]
        manifest = qrl_pb2.TransactionPoolManifest(txhashes=txhashes)
        return manifest

    def load_txs_from_state(self):
        # Read persistent TXPool from LevelDB or start with empty TXPool
        try:
            manifest_raw = self.chain_manager.get_manifest_of_txpool()
        except KeyError:
            logger.info('No saved TransactionPool in State, continuing with empty TransactionPool')
        else:
            manifest = qrl_pb2.TransactionPoolManifest()
            manifest.ParseFromString(manifest_raw)
            for txhash in manifest.txhashes:
                tx_metadata = TransactionMetadata.deserialize(
                    self.chain_manager.get_tx_from_txpool(txhash))
                self.add_tx_to_pool(Transaction.from_pbdata(tx_metadata.transaction), tx_metadata.block_number,
                                    tx_metadata.timestamp, persistent=False)

    @property
    def transactions(self):
        return heapq.nlargest(len(self.transaction_pool), self.transaction_pool)

    def set_broadcast_tx(self, broadcast_tx):
        self.broadcast_tx = broadcast_tx

    def get_pending_transaction(self):
        if len(self.pending_tx_pool_hash) == 0:
            return None
        pending_tx_set = heapq.heappop(self.pending_tx_pool)
        pending_tx = pending_tx_set[1].transaction
        timestamp = pending_tx_set[1].timestamp
        self.pending_tx_pool_hash.remove(pending_tx.txhash)

        return pending_tx, timestamp

    def is_full_pending_transaction_pool(self, ignore_reserve=True) -> bool:
        max_pool_size = config.user.pending_transaction_pool_size

        if ignore_reserve:
            max_pool_size = max_pool_size - config.user.pending_transaction_pool_reserve

        if len(self.pending_tx_pool) >= max_pool_size:
            return True

        return False

    def is_full_transaction_pool(self) -> bool:
        if len(self.transaction_pool) >= config.user.transaction_pool_size:
            return True

        return False

    def update_pending_tx_pool(self, tx, ip, ignore_reserve=True) -> bool:
        if self.is_full_pending_transaction_pool(ignore_reserve):
            return False

        idx = self.get_tx_index_from_pool(tx.txhash)
        if idx > -1:
            return False

        if isinstance(tx, CoinBase):
            logger.warning('Rejected CoinBase Transaction as received without block')
            return False

        if tx.txhash in self.pending_tx_pool_hash:
            return False

        # Since its a min heap giving priority to lower number
        # So -1 multiplied to give higher priority to higher txn
        heapq.heappush(self.pending_tx_pool, [tx.fee * -1, TransactionInfo(tx, -1), ip])
        self.pending_tx_pool_hash.add(tx.txhash)

        return True

    def _prepare_txpool_for_serialization(tx_info: TransactionInfo) -> tuple:
        tx_meta = TransactionMetadata.create(tx=tx_info.transaction,
                                             block_number=tx_info.block_number,
                                             timestamp=tx_info.timestamp)
        txhash_txmeta = (tx_info.transaction.txhash, tx_meta.serialize())
        return txhash_txmeta

    def add_tx_to_pool(self, tx_class_obj, block_number, timestamp: int = None, persistent=True) -> bool:
        """
        if pool is full, return False
        wrap transaction in TransactionInfo and put it into self.transaction_pool
        if persistent, tell State to write manifest and arguments into database.
        """
        if self.is_full_transaction_pool():
            return False

        tx_info = TransactionInfo(tx_class_obj, block_number, timestamp)
        heapq.heappush(self.transaction_pool, [tx_class_obj.fee, tx_info])

        if persistent:
            txhash_txmeta = self._prepare_txinfo_for_serialization(tx_info)
            self.chain_manager.add_txs_to_txpool(self.manifest.SerializeToString(), [txhash_txmeta])

        return True

    @classmethod
    def _prepare_txinfo_for_serialization(cls, tx_info: TransactionInfo) -> tuple:
        """
        Convenience function to prepare arguments for talking to ChainManager.
        :param tx_info:
        :return:
        """
        tx_meta = TransactionMetadata.create(tx=tx_info.transaction,
                                             block_number=tx_info.block_number,
                                             timestamp=tx_info.timestamp)
        txhash_txmeta = (tx_info.transaction.txhash, tx_meta.serialize())
        return txhash_txmeta

    def add_txs_to_pool(self, txs: List[Transaction], block_number, persistent=True) -> bool:
        """
        for each transaction
            if pool is full, remember to return False
            wrap transaction in TransactionInfo and put it into self.transaction_pool
        if persistent, tell State to write manifest and arguments into database.
        """
        txs_added_to_pool = []
        success_complete = True

        for tx in txs:
            if self.is_full_transaction_pool():
                success_complete = False
                break

            tx_info = TransactionInfo(tx, block_number, None)
            txs_added_to_pool.append(tx_info)
            heapq.heappush(self.transaction_pool, [tx.fee, tx_info])

        if persistent:
            txs_added_to_pool_txmeta = [self._prepare_txinfo_for_serialization(s) for s in txs_added_to_pool]
            self.chain_manager.add_txs_to_txpool(self.manifest.SerializeToString(), txs_added_to_pool_txmeta)

        return success_complete

    def get_tx_index_from_pool(self, txhash):
        for i in range(len(self.transaction_pool)):
            txn = self.transaction_pool[i][1].transaction
            if txhash == txn.txhash:
                return i

        return -1

    def remove_tx_from_pool(self, tx: Transaction, persistent=True):
        idx = self.get_tx_index_from_pool(tx.txhash)
        if idx > -1:
            del self.transaction_pool[idx]
            heapq.heapify(self.transaction_pool)
            if persistent:
                self.chain_manager.remove_txs_from_txpool(self.manifest.SerializeToString(), [tx.txhash])

    def remove_txs_from_pool(self, txs: List[Transaction], persistent=True):
        txs_removed_from_pool = []
        for tx in txs:
            self.remove_tx_from_pool(tx, persistent=False)
            txs_removed_from_pool.append(tx.txhash)

        if persistent:
            self.chain_manager.remove_txs_from_txpool(self.manifest.SerializeToString(), txs_removed_from_pool)

    def remove_tx_in_block_from_pool(self, block_obj: Block):
        """
        for each tx in the block, remove it from the pool (if it uses otstype bitfield).
        if it invalidates other txs in the pool through otstype counter, remove those txs from the pool (but not the one from the block)

        Why use a set here? If there are 2 txs in the block that invalidate the same txs in the pool, then those txs in
        the pool will be in txs_to_remove twice. The DB won't complain if you tell it to remove the same tx twice, but
        for cleanliness's sake...
        """
        txs_to_remove = set()
        for protobuf_tx in block_obj.transactions[1:]:  # Ignore first transaction, as it is a coinbase
            tx_from_block = Transaction.from_pbdata(protobuf_tx)
            if tx_from_block.ots_type == OTSType.BITFIELD:
                txs_to_remove.add(tx_from_block)
            else:
                i = 0
                while i < len(self.transaction_pool):
                    tx_from_pool = self.transaction_pool[i][1].transaction
                    if tx_from_block.ots_invalidates(tx_from_pool):
                        txs_to_remove.add(tx_from_pool)
                    i += 1

        self.remove_txs_from_pool(list(txs_to_remove))

    def add_tx_from_block_to_pool(self, block: Block, current_block_number):
        """
        for each transaction in the Block, except the CoinBase:
            add/batch add to TransactionPool with persistence
        """
        txs = [Transaction.from_pbdata(protobuf_tx) for protobuf_tx in block.transactions[1:]]
        success = self.add_txs_to_pool(txs, current_block_number)
        if not success:
            logger.warning('Failed to Add transaction into transaction pool')
            logger.warning('Block #%s %s', block.block_number, bin2hstr(block.headerhash))
            return

    def check_stale_txn(self, state, current_block_number):
        i = 0
        while i < len(self.transaction_pool):
            tx_info = self.transaction_pool[i][1]
            if tx_info.is_stale(current_block_number):
                if not tx_info.validate(state):
                    logger.warning('Txn validation failed for tx in tx_pool')
                    self.remove_tx_from_pool(tx_info.transaction)
                    continue

                tx_info.update_block_number(current_block_number)
                self.broadcast_tx(tx_info.transaction)
            i += 1
