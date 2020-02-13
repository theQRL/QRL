# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import functools
import threading

from pyqrandomx.pyqrandomx import PoWHelper

from qrl.core.Singleton import Singleton


class QRXPoWValidator(object, metaclass=Singleton):
    def __init__(self):
        self.lock = threading.Lock()
        self._powv = PoWHelper()

    def verify_input(self, block_number, seed_height, seed_hash, mining_blob, target):
        return self._verify_input_cached(block_number, seed_height, seed_hash, mining_blob, target)

    @functools.lru_cache(maxsize=5)
    def _verify_input_cached(self, block_number: int, seed_height: int,
                             seed_hash: bytes, mining_blob: bytes, target: bytes):
        return self._powv.verifyInput(block_number, seed_height, seed_hash, mining_blob, target)
