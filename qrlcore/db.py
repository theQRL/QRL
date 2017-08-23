# leveldb code for maintaining account state data
__author__ = 'pete'

import leveldb
import cPickle as pickle
import json


class DB:
    def __init__(self, dbfile='./state'):
        leveldb.DestroyDB(dbfile)
        self.db = leveldb.LevelDB(dbfile)

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

    def destroy(self, dbfile='./state'):
        leveldb.DestroyDB('./state')

    def put(self, key_obj, value_obj):  # serialise with pickle into a string
        dictObj = {'value' : value_obj}
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
