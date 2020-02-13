# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading

from qrl.core import config
from qrl.core.Singleton import Singleton
from qrl.crypto.Qryptonight7 import Qryptonight7
from qrl.crypto.QRandomX import QRandomX


class Qryptonight(object, metaclass=Singleton):

    def __init__(self):
        self.lock = threading.Lock()
        self._qryptonight_7 = Qryptonight7()
        self._qrandom_x = QRandomX()

    def get_qn(self, block_number):
        if block_number < config.dev.hard_fork_heights[0]:
            return self._qryptonight_7
        else:
            return self._qrandom_x

    def get_seed_height(self, block_number):
        return self._qrandom_x.get_seed_height(block_number)

    def hash(self, block_number, seed_height, seed_hash, blob):
        with self.lock:
            if block_number < config.dev.hard_fork_heights[0]:
                return bytes(self._qryptonight_7.hash(blob))
            else:
                return bytes(self._qrandom_x.hash(block_number, seed_height, seed_hash, blob))
