# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from pyqrllib.pyqrllib import bin2hstr
from twisted.internet.task import cooperate

from qrl.core import ChainManager
from qrl.core.TransactionPool import TransactionPool
from qrl.core.misc import logger


class TxnProcessor:
    def __init__(self,
                 chain_manager: ChainManager,
                 transaction_pool_obj: TransactionPool,
                 broadcast_tx):
        self.chain_manager = chain_manager
        self.transaction_pool_obj = transaction_pool_obj
        self.broadcast_tx = broadcast_tx

    def __iter__(self):
        return self

    def __next__(self):
        tx_timestamp = self.transaction_pool_obj.get_pending_transaction()

        if not tx_timestamp:
            raise StopIteration

        tx, timestamp = tx_timestamp

        if not self.chain_manager.validate_all(tx, check_nonce=False):
            return False

        is_valid_pool_state = tx.validate_transaction_pool(self.transaction_pool_obj.transaction_pool)

        if not is_valid_pool_state:
            logger.info('>>>TX %s failed is_valid_pool_state', bin2hstr(tx.txhash))
            return False

        logger.info('A TXN has been Processed %s', bin2hstr(tx.txhash))
        self.transaction_pool_obj.add_tx_to_pool(tx, self.chain_manager.last_block.block_number, timestamp)
        self.broadcast_tx(tx)

        return True

    @staticmethod
    def iterator(iterObj):
        for _ in iterObj:
            yield None

    @staticmethod
    def create_cooperate(iterObj):
        return cooperate(TxnProcessor.iterator(iterObj))
