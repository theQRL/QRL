# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# leveldb code for maintaining account state data
import os

from qrlcore import logger

__author__ = 'pete'

import leveldb
import cPickle as pickle
import json

import configuration as config


class DB:
    def __init__(self):
        self.db_path = os.path.join(config.user.data_path, config.dev.db_name)
        logger.info('DB path: %s', self.db_path)
        os.makedirs(self.db_path)
        # TODO: leveldb python module is not very active. Decouple and replace
        self.destroy()
        self.db = leveldb.LevelDB(self.db_path)

    def return_all_addresses(self):
        addresses = []
        for k, v in self.db.RangeIter('Q'):
            if k[0] == 'Q':
                v = json.loads(v)['value']
                addresses.append([k, v[1]])
        return addresses

    def total_coin_supply(self):
        coins = 0
        for k, v in self.db.RangeIter('Q'):
            if k[0] == 'Q':
                value = json.loads(v)['value']
                coins = coins + value[1]
        return coins

    def zero_all_addresses(self):
        addresses = []
        for k, v in self.db.RangeIter('Q'):
            addresses.append(k)
        for address in addresses:
            self.put(address, [0, 0, []])
        self.put('blockheight', 0)
        return

    def destroy(self):
        leveldb.DestroyDB(self.db_path)

    def put(self, key_obj, value_obj):  # serialise with pickle into a string
        dictObj = {'value': value_obj}
        self.db.Put(key_obj, json.dumps(dictObj))
        return

    def put_batch(self, key_obj, value_obj, batch):  # serialise with pickle into a string
        value_obj = pickle.dumps(value_obj)
        batch.Put(key_obj, value_obj)
        return

    def get(self, key_obj):
        value_obj = self.db.Get(key_obj)
        try:
            return json.loads(value_obj)['value']
        except Exception:
            return value_obj

    def get_batch(self):
        return leveldb.WriteBatch()

    def write_batch(self, batch):
        self.db.Write(batch, sync=True)

    def delete(self, key_obj):
        self.db.Delete(key_obj)
        return
