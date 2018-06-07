# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

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
