# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config
from qrl.core.misc import logger
from qrl.generated import qrl_pb2


class PaginatedData:
    def __init__(self, name: bytes, write_access: bool, db):
        self.name = name
        self.key_value = dict()
        self.db = db
        self.write_access = write_access

    def reset_key_value(self):
        self.key_value = dict()

    def get_value(self, key: bytes, count: int) -> list:
        storage_key = self.generate_key(key, count)
        return self.key_value[storage_key]

    def insert(self, address_state, value: bytes):
        key = address_state.address
        count = address_state.get_counter_by_name(self.name)
        storage_key = self.generate_key(address_state.address, count)

        if storage_key not in self.key_value:
            self.key_value[storage_key] = self.get_paginated_data(key, count)

        self.key_value[storage_key].append(value)

        address_state.update_counter_by_name(self.name)

    def remove(self, address_state, value: bytes):
        address_state.update_counter_by_name(self.name, value=1, subtract=True)

        key = address_state.address
        count = address_state.get_counter_by_name(self.name)
        storage_key = self.generate_key(address_state.address, count)

        if storage_key not in self.key_value:
            self.key_value[storage_key] = self.get_paginated_data(key, count)

        if self.key_value[storage_key][-1] != value:
            logger.warning("Expected value %s", self.key_value[storage_key][-1])
            logger.warning("Found value %s", value)
            raise Exception("Unexpected value into storage")

        del self.key_value[storage_key][-1]

    """
    states_with_counter: It could be address state, vote stats, proposal vote stats, proposal record 
    """
    # def put_paginated_data(self, states_with_counter: dict, batch) -> bool:
    #     data = dict()
    #     key_value = self.key_value
    #     self.key_value = dict()
    #     for key in key_value:
    #         my_state = states_with_counter[key]
    #         t = self.get_paginated_data(key=key,
    #                                     count=my_state.get_counter_by_name(self.name))
    #         my_state.update_counter_by_name(self.name, len(t), subtract=True)
    #         t.extend(key_value[key])
    #         data[key] = t
    #
    #     for key in data:
    #         full_hashes = data[key]
    #         start = 0
    #         hashes = full_hashes[start:start + config.dev.data_per_page]
    #         while hashes:
    #             my_state = states_with_counter[key]
    #             self.put(key,
    #                      my_state.get_counter_by_name(self.name),
    #                      hashes,
    #                      batch)
    #             my_state.update_counter_by_name(self.name, len(hashes))
    #             start += config.dev.data_per_page
    #             hashes = full_hashes[start:start + config.dev.data_per_page]
    #
    #     return True

    def put_paginated_data(self, batch) -> bool:
        key_value = self.key_value
        self.key_value = dict()
        for storage_key in key_value:
            value = key_value[storage_key]
            if len(value) == 0:
                self.delete(storage_key, batch)
            self.put(storage_key, value, batch)

        return True

    def get_paginated_data(self, key, count) -> list:
        storage_key = self.generate_key(key, count)
        try:
            pbData = self.db.get_raw(storage_key)
            data_list = qrl_pb2.DataList()
            data_list.ParseFromString(bytes(pbData))
            return list(data_list.values)
        except KeyError:
            return []
        except Exception as e:
            logger.error('[get_paginated_data] Exception for %s', self.name)
            logger.exception(e)
            raise

    def generate_key(self, key, count: int):
        page = count // config.dev.data_per_page
        return self.name + b'_' + key + b'_' + str(page).encode()

    def put(self, storage_key, value, batch):
        if not self.write_access:
            return
        data_list = qrl_pb2.DataList(values=value)
        self.db.put_raw(storage_key,
                        data_list.SerializeToString(),
                        batch)

    def delete(self, storage_key, batch):
        if not self.write_access:
            return
        self.db.delete(storage_key,
                       batch)

    # def revert_paginated_data(self, states_with_counter: dict, batch) -> bool:
    #     key_value = self.key_value
    #     self.key_value = dict()
    #     for key in key_value:
    #         v = states_with_counter[key]
    #         data = self.get_paginated_data(key, v.get_counter_by_name(self.name))
    #
    #         for value in key_value[key]:
    #             if data[-1] != value:
    #                 logger.warning("Mismatch Paginated data", data[-5:], value)
    #                 return False
    #             del data[-1]
    #             v.update_counter_by_name(self.name, subtract=True)
    #             if len(data) == 0:
    #                 self.delete(key,
    #                             v.get_counter_by_name(self.name),
    #                             batch)
    #                 if v.get_counter_by_name(self.name) > 0:
    #                     data = self.get_paginated_data(key,
    #                                                    v.get_counter_by_name(self.name) - 1)
    #
    #         if data:
    #             self.put(key,
    #                      v.get_counter_by_name(self.name),
    #                      data,
    #                      batch)
    #
    #     return True
