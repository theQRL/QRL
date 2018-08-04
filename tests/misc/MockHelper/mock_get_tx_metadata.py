# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core.txs.Transaction import Transaction


class GetTXMetadata:
    def __init__(self):
        self.data = dict()

    def register_tx_metadata(self, tx: Transaction, block_number: int):
        self.data[tx.txhash] = [tx, block_number]

    def get_tx_metadata(self, txhash):
        if txhash in self.data:
            return self.data[txhash]

        return None

    def remove_txhash(self, txhash):
        del self.data[txhash]
