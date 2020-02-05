# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config
from qrl.core.misc import ntp
from qrl.core.txs.Transaction import Transaction


class TransactionInfo:

    def __init__(self, tx: Transaction, block_number: int, timestamp: int=None):
        self._transaction = tx
        self._block_number = block_number
        self._timestamp = timestamp
        if not self._timestamp:
            self._timestamp = ntp.getTime()

    def __lt__(self, tx_info):
        if self.transaction.fee < tx_info.transaction.fee:
            return True

        return False

    @property
    def transaction(self):
        return self._transaction

    @property
    def block_number(self):
        return self._block_number

    @property
    def timestamp(self):
        return self._timestamp

    def is_stale(self, current_block_number: int):
        if current_block_number > self._block_number + config.user.stale_transaction_threshold:
            return True

        # If chain recovered from a fork where chain height is reduced
        # then update block_number of the transactions in pool
        if current_block_number < self._block_number:
            self.update_block_number(current_block_number)

        return False

    def update_block_number(self, current_block_number: int):
        self._block_number = current_block_number

    def validate(self, new_state_container, update_state_container, block_number) -> bool:
        addresses_set = set()
        self.transaction.set_affected_address(addresses_set)
        state_container = new_state_container(addresses_set,
                                              block_number,
                                              False,
                                              None)

        if not update_state_container(self.transaction, state_container):
            return False

        # Nonce should not be checked during transaction validation,
        # as the appropriate nonce can be set by miner before placing
        # the txn into block
        if not self.transaction.validate_all(state_container, False):
            return False
        return True
