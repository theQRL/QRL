# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.generated.qrl_pb2 import SlaveMetadata


class Indexer:
    def __init__(self, name: bytes, db):
        self._name = name
        self._db = db
        # self._data = IndexerData(self._name)
        self._data = dict()

    @property
    def data(self):
        return self._data

    def put(self, batch=None):
        for key, value in self._data.items():
            if not value.delete:
                self._db.put_raw(self.generate_key(key), value.SerializeToString(), batch)
            else:
                self._db.delete(self.generate_key(key), batch)

    def load(self, key) -> bool:
        generated_key = self.generate_key(key)
        try:
            slaves_meta_data = SlaveMetadata()
            self._data[key] = slaves_meta_data.ParseFromString(self._db.get_raw(generated_key))
        except Exception:
            return False

        return True

    def remove(self, batch=None):
        for key in self._data.items():
            self._db.delete(self.generate_key(key), batch)

    def generate_key(self, keys) -> bytes:
        if not isinstance(keys, tuple):
            raise Exception("Keys are not of type tuple for IndexerData")
        new_key = self._name

        for key in keys:
            if not isinstance(key, bytes):
                if not isinstance(key, str):
                    raise Exception("Invalid key datatype, neither bytes nor string")
                key = key.encode()
            new_key += b'_' + key

        return new_key
