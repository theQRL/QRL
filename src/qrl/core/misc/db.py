# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# leveldb code for maintaining account state data
import plyvel
import os

from qrl.core import config
from qrl.core.misc import logger

__author__ = 'pete'


class DB:
    def __init__(self, db_dir=None):
        self.db_dir = os.path.join(config.user.data_dir, config.dev.db_name)
        if db_dir:
            self.db_dir = db_dir
        logger.info('DB path: %s', self.db_dir)

        os.makedirs(self.db_dir, exist_ok=True)

        try:
            self.db = plyvel.DB(self.db_dir, max_open_files=1000, lru_cache_size=5 * 1024)
        except Exception:
            self.db = plyvel.DB(self.db_dir,
                                max_open_files=1000,
                                lru_cache_size=5 * 1024,
                                create_if_missing=True,
                                compression='snappy')
            self.db.put(b'state_version', str(config.dev.state_version).encode())

    def close(self):
        del self.db

    def open(self, db_dir=None):
        if db_dir:
            self.db_dir = db_dir
        self.db = plyvel.DB(self.db_dir, max_open_files=1000, lru_cache_size=5 * 1024)

    def RangeIter(self, key_obj_start, key_obj_end):
        if not isinstance(key_obj_start, bytes):
            key_obj_start = key_obj_start.encode()

        if not isinstance(key_obj_end, bytes):
            key_obj_end = key_obj_end.encode()

        return self.db.RangeIter(key_obj_start, key_obj_end)

    def get_db_keys(self, include_value: bool):
        return self.db.RangeIter(include_value=include_value)

    def delete(self, key_obj: bytes, batch=None):
        if batch:
            batch.delete(key_obj)
        else:
            self.db.delete(key_obj)

    def put_raw(self, key, value, batch=None):
        if batch:
            batch.put(key, value)
        else:
            self.db.put(key, value)

    def get_raw(self, key):
        if isinstance(key, str):
            key = bytes(key, 'utf-8')
        value = self.db.get(key)
        if value is None:
            raise KeyError
        return value

    def get_batch(self):
        return self.db.write_batch()

    @staticmethod
    def write_batch(batch, sync=True):
        batch.write()
