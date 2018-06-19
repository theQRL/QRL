# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# leveldb code for maintaining account state data
import leveldb
import os

from qrl.core import config
from qrl.core.misc import logger

__author__ = 'pete'


class DB:
    def __init__(self):
        self.db_dir = os.path.join(config.user.data_dir, config.dev.db_name)
        logger.info('DB path: %s', self.db_dir)

        os.makedirs(self.db_dir, exist_ok=True)

        # TODO: leveldb python module is not very active. Decouple and replace
        self.db = leveldb.LevelDB(self.db_dir)

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
            batch.Delete(key_obj)
        else:
            self.db.Delete(key_obj)

    def put_raw(self, key, value, batch=None):
        if batch:
            batch.Put(key, value)
        else:
            self.db.Put(key, value)

    def get_raw(self, key):
        if isinstance(key, str):
            key = bytes(key, 'utf-8')
        return self.db.Get(key)

    def get_batch(self):
        return leveldb.WriteBatch()

    def write_batch(self, batch):
        self.db.Write(batch, sync=True)
