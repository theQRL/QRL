# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# leveldb code for maintaining account state data
import leveldb
import os
import simplejson as json

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

    def put(self, key_obj, value_obj, batch=None):  # serialise with pickle into a string
        if not isinstance(key_obj, bytes) and not isinstance(key_obj, bytearray):
            key_obj = key_obj.encode()

        # FIXME: Bottleneck
        dictObj = {'value': value_obj}
        tmp_json = json.dumps(dictObj).encode()
        if batch:
            batch.Put(key_obj, tmp_json)
        else:
            self.db.Put(key_obj, tmp_json)

    def get(self, key_obj):
        if not isinstance(key_obj, bytes):
            key_obj = key_obj.encode()

        value_obj = self.db.Get(key_obj)
        try:
            # FIXME: This is a massive bottleneck as start up.
            return json.loads(value_obj.decode())['value']
        except KeyError:
            logger.debug("Key not found %s", key_obj)
        except Exception as e:
            logger.exception(e)

    def delete(self, key_obj, batch=None):
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
