# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.LastTransactions import LastTransactions
from qrl.core.txs.Transaction import Transaction
from qrl.generated import qrlstateinfo_pb2


class TransactionMetadata:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrlstateinfo_pb2.TransactionMetadata()

    @property
    def transaction(self):
        return self._data.transaction

    @property
    def block_number(self):
        return self._data.block_number

    @property
    def timestamp(self):
        return self._data.timestamp

    @staticmethod
    def create(tx: Transaction, block_number: int, timestamp: int):
        tm = TransactionMetadata()

        tm._data.transaction.MergeFrom(tx.pbdata)
        tm._data.block_number = block_number
        tm._data.timestamp = timestamp

        return tm

    def serialize(self) -> str:
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrlstateinfo_pb2.TransactionMetadata()
        pbdata.ParseFromString(bytes(data))
        return TransactionMetadata(pbdata)

    @staticmethod
    def put_tx_metadata(state: State, txn: Transaction, block_number: int, timestamp: int, batch) -> bool:
        try:
            tm = TransactionMetadata.create(tx=txn,
                                            block_number=block_number,
                                            timestamp=timestamp)
            state._db.put_raw(txn.txhash,
                              tm.serialize(),
                              batch)
        except Exception:
            logger.warning("Error writing tx metadata")
            return False

        return True

    @staticmethod
    def get_tx_metadata(state: State, txhash: bytes):
        try:
            tx_metadata = TransactionMetadata.deserialize(state._db.get_raw(txhash))
            data, block_number = tx_metadata.transaction, tx_metadata.block_number
            return Transaction.from_pbdata(data), block_number
        except Exception:
            return None

    @staticmethod
    def rollback_tx_metadata(state: State, block, batch):
        fee_reward = 0
        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            fee_reward += txn.fee
            TransactionMetadata.remove_tx_metadata(state, txn, batch)

        txn = Transaction.from_pbdata(block.transactions[0])  # Coinbase Transaction
        state._update_total_coin_supply(fee_reward - txn.amount, batch)
        LastTransactions._remove_last_tx(state, block, batch)

    @staticmethod
    def update_tx_metadata(state: State, block, batch) -> bool:
        fee_reward = 0

        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            fee_reward += txn.fee
            if not TransactionMetadata.put_tx_metadata(state,
                                                       txn,
                                                       block.block_number,
                                                       block.timestamp,
                                                       batch):
                return False

        txn = Transaction.from_pbdata(block.transactions[0])  # Coinbase Transaction
        state._update_total_coin_supply(txn.amount - fee_reward, batch)
        LastTransactions._update_last_tx(state, block, batch)

        return True

    @staticmethod
    def remove_tx_metadata(state: State, txn, batch) -> bool:
        try:
            state._db.delete(txn.txhash, batch)
        except KeyError:
            logger.warning("Error removing tx metadata")
            return False

        return True
