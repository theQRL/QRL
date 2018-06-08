# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core.txs.Transaction import Transaction
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
