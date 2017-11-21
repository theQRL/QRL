# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import logger, config
from twisted.internet.task import cooperate
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.BufferedChain import BufferedChain


class TxnProcessor:
    def __init__(self,
                 buffered_chain: BufferedChain,
                 pending_tx_pool,
                 transaction_pool):
        self.pending_tx_pool = pending_tx_pool
        self.buffered_chain = buffered_chain
        self.transaction_pool = transaction_pool

    def add_tx_to_pool(self, tx):
        self.transaction_pool.append(tx)

    def __iter__(self):
        return self

    def __next__(self):
        if not self.pending_tx_pool:
            raise StopIteration

        if len(self.transaction_pool) >= config.dev.transaction_pool_size:
            raise StopIteration

        tx = self.pending_tx_pool.pop(0)
        tx = tx[0]

        if not tx.validate():
            return False

        tx_state = self.buffered_chain.get_stxn_state(blocknumber=self.buffered_chain.height,
                                                      addr=tx.txfrom)

        is_valid_state = tx.validate_extended(tx_state=tx_state,
                                              transaction_pool=self.transaction_pool)

        if not is_valid_state:
            logger.info('>>>TX %s failed state_validate', tx.txhash)
            return False

        logger.info('A TXN has been Processed %s', bin2hstr(tx.txhash))
        self.add_tx_to_pool(tx)

        return True

    @staticmethod
    def iterator(iterObj):
        for _ in iterObj:
            yield None

    @staticmethod
    def create_cooperate(iterObj):
        return cooperate(TxnProcessor.iterator(iterObj))
