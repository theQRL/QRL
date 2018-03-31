# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config
from qrl.core.Transaction import Transaction
from qrl.core.misc import ntp


class TransactionInfo:

    def __init__(self, tx: Transaction):
        self._transaction = tx
        self._timestamp = ntp.getTime()

    @property
    def transaction(self):
        return self._transaction

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def is_stale(self):
        if self.timestamp + config.user.stale_transaction_threshold < ntp.getTime():
            return True

        return False

    def update_timestamp(self):
        self._timestamp = ntp.getTime()

    def __lt__(self, tx_info):
        if self.transaction.fee < tx_info.transaction.fee:
            return True

        return False
