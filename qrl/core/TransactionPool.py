from collections import OrderedDict
from time import time
from typing import Union

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.Transaction import Transaction, DuplicateTransaction, StakeTransaction, DestakeTransaction


class TransactionPool:
    # FIXME: Remove tx pool from all method names
    def __init__(self):
        self.duplicate_tx_pool = OrderedDict()  # FIXME: Everyone is touching this
        self.pending_tx_pool = []
        self.pending_tx_pool_hash = []
        self.transaction_pool = []  # FIXME: Everyone is touching this
        self.txhash_timestamp = []  # FIXME: Seems obsolete? Delete?

    def add_tx_to_duplicate_pool(self, duplicate_txn: DuplicateTransaction):
        if len(self.duplicate_tx_pool) >= config.dev.transaction_pool_size:
            self.duplicate_tx_pool.popitem(last=False)

        self.duplicate_tx_pool[duplicate_txn.get_message_hash()] = duplicate_txn

    def update_pending_tx_pool(self, tx, peer):
        if len(self.pending_tx_pool) >= config.dev.transaction_pool_size:
            del self.pending_tx_pool[0]
            del self.pending_tx_pool_hash[0]
        self.pending_tx_pool.append([tx, peer])
        self.pending_tx_pool_hash.append(tx.txhash)

    def add_tx_to_pool(self, tx_class_obj: Union[StakeTransaction, DestakeTransaction]):
        self.transaction_pool.append(tx_class_obj)
        self.txhash_timestamp.append(tx_class_obj.txhash)
        self.txhash_timestamp.append(time())

    def remove_tx_from_pool(self, tx_class_obj: Union[StakeTransaction, DestakeTransaction]):
        self.transaction_pool.remove(tx_class_obj)
        self.txhash_timestamp.pop(self.txhash_timestamp.index(tx_class_obj.txhash) + 1)
        self.txhash_timestamp.remove(tx_class_obj.txhash)

    def remove_tx_in_block_from_pool(self, block_obj: Block):
        for protobuf_tx in block_obj.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            for txn in self.transaction_pool:
                if tx.txhash == txn.txhash:
                    self.remove_tx_from_pool(txn)
