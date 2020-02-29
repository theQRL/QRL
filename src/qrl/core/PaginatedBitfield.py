# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from math import ceil

from qrl.core import config
from qrl.core.PaginatedData import PaginatedData
from qrl.core.misc import logger
from qrl.generated import qrl_pb2


class PaginatedBitfield(PaginatedData):
    def __init__(self, write_access: bool, db):
        super(PaginatedBitfield, self).__init__(b'bitfield', write_access, db)

    def generate_bitfield_key(self, address, page):
        return self.name + b'_' + address + b'_' + page.to_bytes(8, byteorder='big', signed=False)

    def load_bitfield_and_ots_key_reuse(self, address, ots_key_index) -> bool:
        page = (ots_key_index // config.dev.ots_tracking_per_page) + 1
        key = self.generate_bitfield_key(address, page)
        self.load_bitfield(address, ots_key_index)
        ots_bitfield = self.key_value[key]

        return self.ots_key_reuse(ots_bitfield, ots_key_index)

    @staticmethod
    def ots_key_reuse(ots_bitfield, ots_key_index) -> bool:
        offset = ots_key_index >> 3
        relative = ots_key_index % 8
        bitfield = bytearray(ots_bitfield[offset])
        bit_value = (bitfield[0] >> relative) & 1

        if bit_value:
            return True

        return False

    def set_ots_key(self, addresses_state: dict, address, ots_key_index):
        page = ots_key_index // config.dev.ots_tracking_per_page + 1
        key = self.generate_bitfield_key(address, page)
        self.load_bitfield(address, ots_key_index)
        ots_bitfield = self.key_value[key]

        ots_key_index = ots_key_index % config.dev.ots_tracking_per_page
        offset = ots_key_index >> 3
        relative = ots_key_index % 8
        bitfield = bytearray(ots_bitfield[offset])
        ots_bitfield[offset] = bytes([bitfield[0] | (1 << relative)])
        address_state = addresses_state[address]
        address_state.used_ots_key_count += 1
        self.update_used_page_in_address_state(address, addresses_state, page)

    def update_used_page_in_address_state(self, address, addresses_state: dict, page: int):
        # TODO: Write Unit Test
        address_state = addresses_state[address]
        if address_state.ots_bitfield_used_page == page - 1:
            remaining_ots = 2 ** address_state.height - (page - 1) * config.dev.ots_tracking_per_page
            while remaining_ots > 0:
                key = self.generate_bitfield_key(address, page)
                if key not in self.key_value:
                    self.key_value[key] = self.get_paginated_data(address, page)
                ots_bitfield = self.key_value[key]

                for i in range(min(config.dev.ots_bitfield_size, ceil(remaining_ots / 8))):
                    if ots_bitfield[i] != b'\xff':
                        return
                    if remaining_ots >= 8:
                        remaining_ots -= 8
                address_state.ots_bitfield_used_page = page  # TODO: Replace by setter function
                page += 1
                if page * config.dev.ots_tracking_per_page > 2 ** address_state.height:
                    return

    def unset_ots_key(self, addresses_state: dict, address, ots_key_index):
        page = ots_key_index // config.dev.ots_tracking_per_page + 1
        key = self.generate_bitfield_key(address, page)
        self.load_bitfield(address, ots_key_index)
        ots_bitfield = self.key_value[key]

        ots_key_index = ots_key_index % config.dev.ots_tracking_per_page
        offset = ots_key_index >> 3
        relative = ots_key_index % 8
        bitfield = bytearray(ots_bitfield[offset])
        ots_bitfield[offset] = bytes([bitfield[0] & ~(1 << relative)])
        address_state = addresses_state[address]
        address_state.used_ots_key_count -= 1
        if address_state.ots_bitfield_used_page >= page:
            address_state.ots_bitfield_used_page = page - 1  # TODO: Replace by setter function

    def load_bitfield(self, address, ots_key_index):
        page = (ots_key_index // config.dev.ots_tracking_per_page) + 1
        key = self.generate_bitfield_key(address, page)
        if key not in self.key_value:
            self.key_value[key] = self.get_paginated_data(address, page)

    def get_paginated_data(self, key, page):
        try:
            pbData = self.db.get_raw(self.name + b'_' + key + b'_' + page.to_bytes(8, byteorder='big', signed=False))
            data_list = qrl_pb2.DataList()
            data_list.ParseFromString(bytes(pbData))
            return list(data_list.values)
        except KeyError:
            return [b'\x00'] * config.dev.ots_bitfield_size
        except Exception as e:
            logger.error('[get_paginated_data] Exception for %s', self.name)
            logger.exception(e)
            raise

    def put_addresses_bitfield(self, batch):
        if not self.write_access:
            return
        for key in self.key_value:
            data_list = qrl_pb2.DataList(values=self.key_value[key])
            self.db.put_raw(key,
                            data_list.SerializeToString(),
                            batch)
