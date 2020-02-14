# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class Indexer:
    def __init__(self, name: bytes, db):
        self._name = name
        self._db = db
        self._data = dict()

    @property
    def data(self):
        return self._data

    def put(self, batch=None):
        for key, value in self._data.items():
            if value.delete:
                self._db.delete(self.generate_key(key), batch)
                continue

            self._db.put_raw(self.generate_key(key), value.SerializeToString(), batch)

    def load(self, key, meta_data) -> bool:
        generated_key = self.generate_key(key)
        try:
            meta_data.ParseFromString(self._db.get_raw(generated_key))
            self._data[key] = meta_data
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
