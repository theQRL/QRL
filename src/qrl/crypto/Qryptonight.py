# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading

from qrl.core.Singleton import Singleton
from pyqryptonight import pyqryptonight


class Qryptonight(object, metaclass=Singleton):
    """
    Qryptonight is simply a Python wrapper around pyqryptonight.Qryptonight
    (itself a SWIG wrapper around C++ code) but with the extra feature that only
    one thread can use it at a time. This is important because if you use the
    same instance of Qryptonight to hash something while something else is being
    hashed, then the two jobs will step on each others' memory and you will get
    a bad hash. So there has to be a lock.

    Because of the aforementioned issue, one should take care not to have too
    many Qryptonight instances. It is only used in BlockHeader to calculate the
    headerhash and the ChainManager to verify headerhashes.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self._qn = pyqryptonight.Qryptonight()

    def hash(self, blob):
        with self.lock:
            return bytes(self._qn.hash(blob))
