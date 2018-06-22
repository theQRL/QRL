# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from pyqrllib.pyqrllib import shake256

from qrl.core.misc import logger

logger.initialize_default()


class RNG(object):
    """
    A naive implementaiton of RNG
    WARNING: Only for unit testing.
    """
    @staticmethod
    def generate(prf_seed: bytes, seq: int) -> bytes:
        prf = prf_seed
        for i in range(seq):
            prf = shake256(32, prf)

        return bytes(prf)
