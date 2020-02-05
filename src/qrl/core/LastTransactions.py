# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.State import State
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.generated import qrlstateinfo_pb2


class LastTransactions:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrlstateinfo_pb2.LastTransactions()

    @property
    def tx_metadata(self):
        return self._data.tx_metadata

    def add(self, tx: Transaction, block_number: int, timestamp: int):
        tm = qrlstateinfo_pb2.TransactionMetadata(transaction=tx.pbdata,
                                                  block_number=block_number,
                                                  timestamp=timestamp)
        tmp = self._data.tx_metadata[::-1]
        tmp.append(tm)
        del self._data.tx_metadata[:]
        self._data.tx_metadata.extend(tmp[-20:][::-1])

    def serialize(self) -> str:
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrlstateinfo_pb2.LastTransactions()
        pbdata.ParseFromString(bytes(data))
        return LastTransactions(pbdata)

    @staticmethod
    def _remove_last_tx(state: State, block: Block, batch):
        if len(block.transactions) == 0:
            return

        try:
            last_txn = LastTransactions.deserialize(state._db.get_raw(b'last_txn'))
        except KeyError:
            return

        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            i = 0
            while i < len(last_txn.tx_metadata):
                tx = Transaction.from_pbdata(last_txn.tx_metadata[i].transaction)
                if txn.txhash == tx.txhash:
                    del last_txn.tx_metadata[i]
                    break
                i += 1

        state._db.put_raw(b'last_txn', last_txn.serialize(), batch)

    @staticmethod
    def _update_last_tx(state: State, block: Block, batch):
        if len(block.transactions) == 0:
            return
        last_txn = LastTransactions()

        try:
            last_txn = LastTransactions.deserialize(state._db.get_raw(b'last_txn'))
        except KeyError:
            pass

        for protobuf_txn in block.transactions[-20:]:
            txn = Transaction.from_pbdata(protobuf_txn)
            if isinstance(txn, CoinBase):
                continue
            last_txn.add(txn, block.block_number, block.timestamp)

        state._db.put_raw(b'last_txn', last_txn.serialize(), batch)

    @staticmethod
    def get_last_txs(state: State):
        try:
            last_txn = LastTransactions.deserialize(state._db.get_raw(b'last_txn'))
        except KeyError:
            return []
        except Exception as e:  # noqa
            logger.warning("[get_last_txs] Exception during call %s", e)
            return []

        txs = []
        for tx_metadata in last_txn.tx_metadata:
            data = tx_metadata.transaction
            tx = Transaction.from_pbdata(data)
            txs.append(tx)

        return txs
