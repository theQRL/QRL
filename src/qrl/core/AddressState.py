# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from copy import deepcopy
from collections import defaultdict

from pyqrllib.pyqrllib import QRLHelper

from qrl.core import config
from qrl.generated import qrl_pb2


class AddressState(object):
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        self.tokens = defaultdict(int)
        if protobuf_block is None:
            self._data = qrl_pb2.AddressState()
        else:
            for key in self._data.tokens:
                self.tokens[str(key).encode()] = deepcopy(self._data.tokens[key])

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf AddressState object
        :rtype: qrl_pb2.AddressState
        """
        for key in self.tokens:
            self._data.tokens[key] = self.tokens[key]
        return self._data

    @property
    def address(self):
        return self._data.address

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
            address_state.tokens[token_txhash] = tokens[token_txhash]

        for slave_pk in slave_pks_access_type:
            address_state.slave_pks_access_type[str(slave_pk)] = slave_pks_access_type[str(slave_pk)]

        return address_state

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
        for lattice_pk_idx in range(len(self._data.latticePK_list)):
            lattice_pk = self._data.latticePK_list[lattice_pk_idx]
            if lattice_pk.txhash == lattice_txn.txhash:
                del self._data.latticePK_list[lattice_pk_idx]
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

    def unset_ots_key(self, ots_key_index, state):
        if ots_key_index < config.dev.max_ots_tracking_index:
            offset = ots_key_index >> 3
            relative = ots_key_index % 8
            bitfield = bytearray(self._data.ots_bitfield[offset])
            self._data.ots_bitfield[offset] = bytes([bitfield[0] & ~(1 << relative)])
        else:
            self._data.ots_counter = 0  # defaults to 0 in case, no other ots_key found for ots_counter
            # Expected transaction hash has been removed before unsetting ots key for that same transaction
            for tx_hash in self.transaction_hashes[-1::-1]:
                tx, _ = state.get_tx_metadata(tx_hash)
                if tx.ots_key >= config.dev.max_ots_tracking_index:
                    self._data.ots_counter = tx.ots_key
                    break

    @staticmethod
    def address_is_valid(address: bytes) -> bool:
        if not QRLHelper.addressIsValid(address):
            return False

        return True

    def serialize(self):
        return self._data.SerializeToString()
