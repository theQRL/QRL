# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# leveldb code for maintaining account state data
import pickle as pickle
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

    def RangeIter(self, *args, **kwargs):
        return self.db.RangeIter(args, kwargs)

    def put(self, key_obj, value_obj):  # serialise with pickle into a string
        dictObj = {'value': value_obj}
        self.db.Put(key_obj.encode(), json.dumps(dictObj).encode())
        return

    def put_batch(self, key_obj, value_obj, batch):  # serialise with pickle into a string
        value_obj = pickle.dumps(value_obj)
        batch.Put(key_obj.encode(), value_obj.encode())
        return

    def get(self, key_obj):
        if not isinstance(key_obj, bytes):
            key_obj = bytes(key_obj, 'utf-8')
        value_obj = self.db.Get(key_obj)
        try:
            return json.loads(value_obj.decode())['value']
        except KeyError as e:
            logger.error("Key not found %s", key_obj)
            logger.exception(e)
        except Exception as e:
            logger.exception(e)

    def get_batch(self):
        return leveldb.WriteBatch()

    def write_batch(self, batch):
        self.db.Write(batch, sync=True)

    def delete(self, key_obj):
        self.db.Delete(key_obj)
        return
