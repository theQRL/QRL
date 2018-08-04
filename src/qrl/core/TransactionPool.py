# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import heapq

from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.TransactionInfo import TransactionInfo


class TransactionPool:
    # FIXME: Remove tx pool from all method names
    def __init__(self, broadcast_tx):
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = set()
        self.transaction_pool = []  # FIXME: Everyone is touching this
        self.broadcast_tx = broadcast_tx

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

    def add_tx_to_pool(self, tx_class_obj, block_number, timestamp: int=None) -> bool:
        if self.is_full_transaction_pool():
            return False

        heapq.heappush(self.transaction_pool, [tx_class_obj.fee, TransactionInfo(tx_class_obj,
                                                                                 block_number,
                                                                                 timestamp)])
        return True

    def get_tx_index_from_pool(self, txhash):
        for i in range(len(self.transaction_pool)):
            txn = self.transaction_pool[i][1].transaction
            if txhash == txn.txhash:
                return i

        return -1

    def remove_tx_from_pool(self, tx: Transaction):
        idx = self.get_tx_index_from_pool(tx.txhash)
        if idx > -1:
            del self.transaction_pool[idx]
            heapq.heapify(self.transaction_pool)

    def remove_tx_in_block_from_pool(self, block_obj: Block):
        for protobuf_tx in block_obj.transactions[1:]:  # Ignore first transaction, as it is a coinbase txn
            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.ots_key < config.dev.max_ots_tracking_index:
                idx = self.get_tx_index_from_pool(tx.txhash)
                if idx > -1:
                    del self.transaction_pool[idx]
            else:
                i = 0
                while i < len(self.transaction_pool):
                    txn = self.transaction_pool[i][1].transaction
                    if txn.PK == tx.PK:
                        if txn.ots_key >= config.dev.max_ots_tracking_index:
                            if txn.ots_key <= tx.ots_key:
                                del self.transaction_pool[i]
                                continue
                    i += 1

        heapq.heapify(self.transaction_pool)

    def add_tx_from_block_to_pool(self, block: Block, current_block_number):
        """
        Move all transactions from block to transaction pool.
        :param block:
        :return:
        """
        for protobuf_tx in block.transactions[1:]:
            if not self.add_tx_to_pool(Transaction.from_pbdata(protobuf_tx), current_block_number):
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
