# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from pyqrllib.pyqrllib import QRLHelper, bin2hstr

from qrl.core import config
from qrl.core.State import State
from qrl.generated import qrl_pb2


class AddressState(object):
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.AddressState()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf AddressState object
        :rtype: qrl_pb2.AddressState
        """
        return self._data

    @property
    def address(self):
        return self._data.address

    @property
    def height(self):
        return self._data.address[1] << 1

    @property
    def nonce(self):
        return self._data.nonce

    @property
    def balance(self):
        return self._data.balance

    @balance.setter
    def balance(self, new_balance: int):
        self._data.balance = new_balance

    @property
    def ots_bitfield(self):
        return self._data.ots_bitfield

    @property
    def ots_counter(self):
        return self._data.ots_counter

    @property
    def transaction_hashes(self):
        return self._data.transaction_hashes

    @property
    def latticePK_list(self):
        return self._data.latticePK_list

    @property
    def slave_pks_access_type(self):
        return self._data.slave_pks_access_type

    @staticmethod
    def create(address: bytes,
               nonce: int,
               balance: int,
               ots_bitfield: list,
               tokens: dict,
               slave_pks_access_type: dict,
               ots_counter: int):
        address_state = AddressState()

        address_state._data.address = address
        address_state._data.nonce = nonce
        address_state._data.balance = balance
        address_state._data.ots_bitfield.extend(ots_bitfield)
        address_state._data.ots_counter = ots_counter

        for token_txhash in tokens:
            address_state.update_token_balance(token_txhash, tokens[token_txhash])

        for slave_pk in slave_pks_access_type:
            address_state.add_slave_pks_access_type(slave_pk, slave_pks_access_type[slave_pk])

        return address_state

    def validate_slave_with_access_type(self, slave_pk: str, access_types: list):
        if slave_pk not in self.slave_pks_access_type:
            return False

        access_type = self.slave_pks_access_type[slave_pk]
        if access_type not in access_types:
            return False

        return True

    def update_token_balance(self, token_tx_hash: bytes, balance: int):
        str_token_tx_hash = bin2hstr(token_tx_hash)
        self._data.tokens[str_token_tx_hash] += balance
        if self._data.tokens[str_token_tx_hash] == 0:
            del self._data.tokens[str_token_tx_hash]

    def get_token_balance(self, token_tx_hash: bytes) -> int:
        str_token_tx_hash = bin2hstr(token_tx_hash)
        if str_token_tx_hash in self._data.tokens:
            return self._data.tokens[str_token_tx_hash]
        return 0

    def is_token_exists(self, token_tx_hash: bytes) -> bool:
        str_token_tx_hash = bin2hstr(token_tx_hash)
        if str_token_tx_hash in self._data.tokens:
            return True
        return False

    def add_slave_pks_access_type(self, slave_pk: bytes, access_type: int):
        self._data.slave_pks_access_type[str(slave_pk)] = access_type

    def remove_slave_pks_access_type(self, slave_pk: bytes):
        del self._data.slave_pks_access_type[str(slave_pk)]

    def add_lattice_pk(self, lattice_txn):
        lattice_pk = qrl_pb2.LatticePK(txhash=lattice_txn.txhash,
                                       dilithium_pk=lattice_txn.dilithium_pk,
                                       kyber_pk=lattice_txn.kyber_pk)

        self._data.latticePK_list.extend([lattice_pk])

    def remove_lattice_pk(self, lattice_txn):
        for i, lattice_pk in enumerate(self._data.latticePK_list):
            if lattice_pk.txhash == lattice_txn.txhash:
                del self._data.latticePK_list[i]
                break

    def increase_nonce(self):
        self._data.nonce += 1

    def decrease_nonce(self):
        self._data.nonce -= 1

    def get_slave_permission(self, slave_pk) -> int:
        slave_pk_str = str(slave_pk)
        if slave_pk_str in self._data.slave_pks_access_type:
            return self._data.slave_pks_access_type[slave_pk_str]

        return -1

    @staticmethod
    def get_default(address):
        address_state = AddressState.create(address=address,
                                            nonce=config.dev.default_nonce,
                                            balance=config.dev.default_account_balance,
                                            ots_bitfield=[b'\x00'] * config.dev.ots_bitfield_size,
                                            tokens=dict(),
                                            slave_pks_access_type=dict(),
                                            ots_counter=0)
        if address == config.dev.coinbase_address:
            address_state.balance = int(config.dev.max_coin_supply * config.dev.shor_per_quanta)
        return address_state

    def ots_key_reuse(self, ots_key_index):
        if ots_key_index < config.dev.max_ots_tracking_index:
            offset = ots_key_index >> 3
            relative = ots_key_index % 8
            bitfield = bytearray(self.ots_bitfield[offset])
            bit_value = (bitfield[0] >> relative) & 1

            if bit_value:
                return True
        else:
            if ots_key_index <= self._data.ots_counter:
                return True

        return False

    def set_ots_key(self, ots_key_index):
        if ots_key_index < config.dev.max_ots_tracking_index:
            offset = ots_key_index >> 3
            relative = ots_key_index % 8
            bitfield = bytearray(self._data.ots_bitfield[offset])
            self._data.ots_bitfield[offset] = bytes([bitfield[0] | (1 << relative)])
        else:
            self._data.ots_counter = ots_key_index

    def unset_ots_key(self, ots_key_index, chain_manager):
        if ots_key_index < config.dev.max_ots_tracking_index:
            offset = ots_key_index >> 3
            relative = ots_key_index % 8
            bitfield = bytearray(self._data.ots_bitfield[offset])
            self._data.ots_bitfield[offset] = bytes([bitfield[0] & ~(1 << relative)])
        else:
            self._data.ots_counter = 0  # defaults to 0 in case, no other ots_key found for ots_counter
            # Expected transaction hash has been removed before unsetting ots key for that same transaction
            for tx_hash in self.transaction_hashes[-1::-1]:
                tx, _ = chain_manager.get_tx_metadata(tx_hash)
                if tx.ots_key >= config.dev.max_ots_tracking_index:
                    self._data.ots_counter = tx.ots_key
                    break

    def get_unused_ots_index(self, start_ots_index=0):
        """
        Finds the unused ots index above the given start_ots_index.
        :param start_ots_index:
        :return:
        """
        ots_key_count = (2 ** self.height)

        for i in range(start_ots_index // 8, min(ots_key_count, config.dev.max_ots_tracking_index) // 8):
            if self.ots_bitfield[i][0] < 255:
                offset = 8 * i
                bitfield = bytearray(self.ots_bitfield[i])
                for relative in range(0, 8):
                    if ((bitfield[0] >> relative) & 1) != 1:
                        if offset + relative >= start_ots_index:
                            return offset + relative

        if ots_key_count >= config.dev.max_ots_tracking_index:
            if self.ots_counter + 1 < ots_key_count:
                if self.ots_counter == 0:
                    return max(config.dev.max_ots_tracking_index, start_ots_index)
                return max(self.ots_counter + 1, start_ots_index)

        return None

    @staticmethod
    def address_is_valid(address: bytes) -> bool:
        # Warning: Never pass this validation True for Coinbase Address
        if not QRLHelper.addressIsValid(address):
            return False

        if address[0:1] == b'\x11':
            return False

        return True

    def serialize(self):
        return self._data.SerializeToString()

    @staticmethod
    def put_addresses_state(state: State, addresses_state: dict, batch=None):
        """
        :param addresses_state:
        :param batch:
        :return:
        """
        for address in addresses_state:
            address_state = addresses_state[address]
            AddressState.put_address_state(state, address_state, batch)

    @staticmethod
    def put_address_state(state: State, address_state, batch=None):
        data = address_state.pbdata.SerializeToString()
        state._db.put_raw(address_state.address, data, batch)

    @staticmethod
    def get_address_state(state: State, address: bytes):
        try:
            data = state._db.get_raw(address)
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            return address_state
        except KeyError:
            return AddressState.get_default(address)

    @staticmethod
    def return_all_addresses(state: State) -> list:
        addresses = []
        for key, data in state._db.db:
            if key[0] != b'Q':
                continue
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            addresses.append(address_state)
        return addresses
