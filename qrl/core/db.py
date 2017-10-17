# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# leveldb code for maintaining account state data
import leveldb
import os
import simplejson as json

from qrl.core import config, logger

__author__ = 'pete'


class DB:
    def __init__(self):
        self.db_path = os.path.join(config.user.data_path, config.dev.db_name)
        logger.info('DB path: %s', self.db_path)

        os.makedirs(self.db_path, exist_ok=True)

        # TODO: leveldb python module is not very active. Decouple and replace
        self.destroy()
        self.db = leveldb.LevelDB(self.db_path)

    def destroy(self):
        leveldb.DestroyDB(self.db_path)

    def RangeIter(self, key_obj_start, key_obj_end):
        if not isinstance(key_obj_start, bytes):
            key_obj_start = key_obj_start.encode()

        if not isinstance(key_obj_end, bytes):
            key_obj_end = key_obj_end.encode()

        return self.db.RangeIter(key_obj_start, key_obj_end)

    def put(self, key_obj, value_obj):  # serialise with pickle into a string
        if not isinstance(key_obj, bytes) and not isinstance(key_obj, bytearray):
            key_obj = key_obj.encode()

        # FIXME: Bottleneck
        dictObj = {'value': value_obj}
        self.db.Put(key_obj, json.dumps(dictObj).encode())

    def get(self, key_obj):
        if not isinstance(key_obj, bytes):
            key_obj = key_obj.encode()

        value_obj = self.db.Get(key_obj)
        try:
            # FIXME: This is a massive bottleneck as start up.
            return json.loads(value_obj.decode())['value']
        except KeyError as e:
            logger.error("Key not found %s", key_obj)
            logger.exception(e)
        except Exception as e:
            logger.exception(e)

    def delete(self, key_obj):
        self.db.Delete(key_obj)

    def put_raw(self, key, value):
        self.db.Put(key, value)

    def get_raw(self, key):
        if isinstance(key, str):
            key = bytes(key, 'utf-8')
        return self.db.Get(key)
