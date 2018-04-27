# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import functools

from pyqryptonight.pyqryptonight import UInt256ToString, Qryptonight, PoWHelper

from qrl.core.BlockHeader import BlockHeader
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.Singleton import Singleton
from qrl.core.misc import logger


class PoWValidator(object, metaclass=Singleton):
    def __init__(self):
        self._powv = PoWHelper()

    def validate_mining_nonce(self, state, blockheader: BlockHeader, enable_logging=False):
        parent_metadata = state.get_block_metadata(blockheader.prev_blockheaderhash)
        parent_block = state.get_block(blockheader.prev_blockheaderhash)

        measurement = state.get_measurement(blockheader.timestamp, blockheader.prev_blockheaderhash, parent_metadata)
        diff, target = DifficultyTracker.get(
            measurement=measurement,
            parent_difficulty=parent_metadata.block_difficulty)

        if enable_logging:
            logger.debug('-----------------START--------------------')
            logger.debug('Validate #%s', blockheader.block_number)
            logger.debug('block.timestamp %s', blockheader.timestamp)
            logger.debug('parent_block.timestamp %s', parent_block.timestamp)
            logger.debug('parent_block.difficulty %s', UInt256ToString(parent_metadata.block_difficulty))
            logger.debug('diff : %s | target : %s', UInt256ToString(diff), target)
            logger.debug('-------------------END--------------------')

        if not self.verify_input_cached(blockheader.mining_blob, target):
            if enable_logging:
                logger.warning("PoW verification failed")
                qn = Qryptonight()
                tmp_hash = qn.hash(blockheader.mining_blob)
                logger.warning("{}".format(tmp_hash))
                logger.debug('%s', blockheader.to_json())
            return False

        return True

    @functools.lru_cache(maxsize=5)
    def verify_input_cached(self, mining_blob, target):
        return PoWValidator()._powv.verifyInput(mining_blob, target)
