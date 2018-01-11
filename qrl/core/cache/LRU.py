# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from pyqrllib.pyqrllib import bin2hstr


class LRUStateCache:
    def __init__(self, size, db):
        self._cache = OrderedDict()
        self._size = size
        self._db = db  # To be used later to store in DB, instead of memory

    def get(self, key):
        key = bin2hstr(key)
        try:
            value = self._cache.pop(key)
            self._cache[key] = value
            # TODO: Load from DB
            return value
        except KeyError:
            return dict()

    def set(self, key, value):
        key = bin2hstr(key)
        try:
            self._cache.pop(key)
        except KeyError:
            if len(self._cache) >= self._size:
                key, _ = self._cache.popitem(last=False)
                # TODO: Delete Key From DB
        self._cache[key] = value
        # TODO: Add Key, value into DB
