# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading

from qrl.core.Singleton import Singleton
from pyqrandomx import pyqrandomx


class QRandomX(object, metaclass=Singleton):

    def __init__(self):
        self.lock = threading.Lock()
        self._qrx = pyqrandomx.ThreadedQRandomX()

    def get_seed_height(self, block_number):
        return self._qrx.getSeedHeight(block_number)

    def hash(self, block_height, seed_height, seed_hash, blob):
        with self.lock:
            return bytes(self._qrx.hash(block_height, seed_height, seed_hash, blob, 0))
