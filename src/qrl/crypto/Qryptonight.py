# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core.Singleton import Singleton
from pyqryptonight import pyqryptonight


class Qryptonight(object, metaclass=Singleton):
    def __init__(self):
        self._qn = pyqryptonight.Qryptonight()

    def hash(self, blob):
        return bytes(self._qn.hash(blob))
