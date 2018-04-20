# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from twisted.internet.task import cooperate
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.misc import logger
from qrl.core.Transaction import Transaction
from qrl.core.TransactionPool import TransactionPool

from qrl.core.State import State


class TxnProcessor:
    def __init__(self,
                 state: State,
                 transaction_pool_obj: TransactionPool,
                 broadcast_tx):
        self.state = state
        self.transaction_pool_obj = transaction_pool_obj
        self.broadcast_tx = broadcast_tx

    def __iter__(self):
        return self

    def __next__(self):
        tx = self.transaction_pool_obj.get_pending_transaction()

        if not tx:
            raise StopIteration

        if not tx.validate():
            return False

        addr_from_state = self.state.get_address_state(address=tx.addr_from)
        addr_from_pk_state = addr_from_state

        addr_from_pk = Transaction.get_slave(tx)
        if addr_from_pk:
            addr_from_pk_state = self.state.get_address_state(address=addr_from_pk)

        is_valid_state = tx.validate_extended(addr_from_state=addr_from_state,
                                              addr_from_pk_state=addr_from_pk_state)

        is_valid_pool_state = tx.validate_transaction_pool(self.transaction_pool_obj.transaction_pool)

        if not (is_valid_state and is_valid_pool_state):
            logger.info('>>>TX %s failed state_validate', bin2hstr(tx.txhash))
            return False

        logger.info('A TXN has been Processed %s', bin2hstr(tx.txhash))
        self.transaction_pool_obj.add_tx_to_pool(tx, self.state.last_block.block_number)
        self.broadcast_tx(tx)

        return True

    @staticmethod
    def iterator(iterObj):
        for _ in iterObj:
            yield None

    @staticmethod
    def create_cooperate(iterObj):
        return cooperate(TxnProcessor.iterator(iterObj))
