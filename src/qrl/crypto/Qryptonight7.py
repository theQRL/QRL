# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading

from qrl.core.Singleton import Singleton
from pyqryptonight import pyqryptonight


class Qryptonight7(object, metaclass=Singleton):

    def __init__(self):
        self.lock = threading.Lock()
        self._qn = pyqryptonight.Qryptonight()

    def hash(self, blob):
        with self.lock:
            return bytes(self._qn.hash(blob))
