# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy

from pyqrandomx.pyqrandomx import QRXMiner, SOLUTION

from qrl.core.config import DevConfig, user as user_config
from qrl.core.Block import Block
from qrl.core.misc import logger
from qrl.crypto.QRandomX import QRandomX


class QRandomXMiner(QRXMiner):
    def __init__(self,
                 chain_manager,
                 pre_block_logic,
                 mining_address: bytes,
                 mining_thread_count,
                 lock):
        super().__init__()
        self._qn = QRandomX()
        self._chain_manager = chain_manager
        self._pre_block_logic = pre_block_logic  # FIXME: Circular dependency with node.py

        self._mining_address = mining_address
        self._mining_thread_count = mining_thread_count

        self._mining_block = None
        self._seed_block = None
        self.setForcedSleep(user_config.mining_pause)
        self._dev_config = None
        self.lock = lock

    def get_seed_block(self, block_number):
        # TODO: Verify when seed height is changed also add unit test for edge case
        seed_height = self._qn.get_seed_height(block_number)
        if self._seed_block is None or self._seed_block.block_number != seed_height:
            self._seed_block = self._chain_manager.get_block_by_number(seed_height)
        return self._seed_block

    def start_mining(self,
                     mining_block: Block,
                     current_target: bytes,
                     dev_config: DevConfig):
        try:
            logger.debug('start_mining - TRY LOCK')
            with self.lock:
                logger.debug('start_mining - LOCKED')
                self.cancel()

                mining_blob = mining_block.mining_blob(dev_config)
                nonce_offset = mining_block.mining_nonce_offset(dev_config)

                seed_block = self.get_seed_block(mining_block.block_number)

                self._dev_config = dev_config
                self._mining_block = mining_block
                work_seq_id = self.start(mainHeight=mining_block.block_number,
                                         seedHeight=seed_block.block_number,
                                         seedHash=seed_block.headerhash,
                                         input=mining_blob,
                                         nonceOffset=nonce_offset,
                                         target=current_target,
                                         thread_count=self._mining_thread_count)

                logger.debug("MINING START [{}]".format(work_seq_id))

        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

        logger.debug('start_mining - UNLOCKED')

    def handleEvent(self, event):
        # NOTE: This function usually runs in the context of a C++ thread
        if event.type == SOLUTION:
            logger.debug('handleEvent - TRY LOCK')
            if not self.lock.acquire(blocking=False):
                logger.debug('handleEvent - SKIP')
                return False

            try:
                logger.debug('handleEvent - LOCKED')

                logger.debug('Solution Found %s', event.nonce)
                logger.info('Hash Rate: %s H/s', self.hashRate())
                cloned_block = copy.deepcopy(self._mining_block)
                cloned_block.set_nonces(self._dev_config, event.nonce, 0)
                logger.debug("Blob           %s", cloned_block)
                logger.info('Block #%s nonce: %s', cloned_block.block_number, event.nonce)
                self._pre_block_logic(cloned_block)
            except Exception as e:
                logger.warning("Exception in solutionEvent")
                logger.exception(e)
            finally:
                logger.debug('handleEvent - UNLOCK')
                self.lock.release()

        return True
