# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import functools
import threading

from pyqryptonight.pyqryptonight import PoWHelper

from qrl.core.Singleton import Singleton


class CNv1PoWValidator(object, metaclass=Singleton):
    def __init__(self):
        self.lock = threading.Lock()
        self._powv = PoWHelper()

    def verify_input(self, mining_blob, target):
        return self._verify_input_cached(mining_blob, target)

    @functools.lru_cache(maxsize=5)
    def _verify_input_cached(self, mining_blob, target):
        return self._powv.verifyInput(mining_blob, target)
