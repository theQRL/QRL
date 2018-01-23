# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from collections import OrderedDict

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.Transaction import Transaction


class TransactionPool:
    # FIXME: Remove tx pool from all method names
    def __init__(self):
        self.duplicate_tx_pool = OrderedDict()  # FIXME: Everyone is touching this
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = []
        self.transaction_pool = []  # FIXME: Everyone is touching this

    def is_full_transaction_pool(self) -> bool:
        if len(self.transaction_pool) >= config.dev.transaction_pool_size:
            return True

        return False

    def update_pending_tx_pool(self, tx, ip):
        if len(self.pending_tx_pool) >= config.dev.transaction_pool_size:
            del self.pending_tx_pool[0]
            del self.pending_tx_pool_hash[0]

        # FIXME: Avoid using indexes, etc
        self.pending_tx_pool.append([tx, ip])
        self.pending_tx_pool_hash.append(tx.txhash)

    def add_tx_to_pool(self, tx_class_obj) -> bool:
        if self.is_full_transaction_pool():
            return False

        self.transaction_pool.append(tx_class_obj)
        return True

    def remove_tx_from_pool(self, tx_class_obj):
        self.transaction_pool.remove(tx_class_obj)

    def remove_tx_in_block_from_pool(self, block_obj: Block):
        for protobuf_tx in block_obj.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            for txn in self.transaction_pool:
                if tx.txhash == txn.txhash:
                    self.remove_tx_from_pool(txn)
