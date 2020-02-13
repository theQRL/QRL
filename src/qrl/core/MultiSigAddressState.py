# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from pyqrllib.pyqrllib import QRLHelper, hstr2bin, sha2_256

from collections import namedtuple
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.generated import qrl_pb2


class MultiSigAddressState(object):
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.MultiSigAddressState()

        counter_mapping = namedtuple("counter_mapping", ["get", "update"])

        self._counter_by_name = {
            b'p_tx_hash': counter_mapping(self.transaction_hash_count,
                                          self.update_transaction_hash_count),
            b'p_multi_sig_spend': counter_mapping(self.multi_sig_spend_count,
                                                  self.update_multi_sig_spend_count),
        }

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf MultiSigAddressState object
        :rtype: qrl_pb2.MultiSigAddressState
        """
        return self._data

    @property
    def address(self):
        return self._data.address

    @property
    def creation_tx_hash(self):
        return self._data.creation_tx_hash

    @property
    def balance(self):
        return self._data.balance

    @property
    def signatories(self):
        return self._data.signatories

    @property
    def weights(self):
        return self._data.weights

    @property
    def threshold(self):
        return self._data.threshold

    # @property
    def transaction_hash_count(self):
        return self._data.transaction_hash_count

    def multi_sig_spend_count(self):
        return self._data.multi_sig_spend_count

    @staticmethod
    def generate_multi_sig_address(creation_tx_hash: bytes) -> bytes:
        desc = bytes(hstr2bin('110000'))
        prev_hash = bytes(sha2_256(desc + creation_tx_hash))
        new_hash = bytes(sha2_256(desc + prev_hash))[-4:]
        return desc + prev_hash + new_hash

    @staticmethod
    def create(creation_tx_hash: bytes,
               balance: int,
               signatories: list,
               weights: list,
               threshold: int,
               transaction_hash_count: int):
        multi_sig_address_state = MultiSigAddressState()

        multi_sig_address_state._data.address = MultiSigAddressState.generate_multi_sig_address(creation_tx_hash)
        multi_sig_address_state._data.creation_tx_hash = creation_tx_hash
        multi_sig_address_state._data.balance = balance
        multi_sig_address_state._data.signatories.extend(signatories)
        multi_sig_address_state._data.weights.extend(weights)
        multi_sig_address_state._data.threshold = threshold
        multi_sig_address_state._data.transaction_hash_count = transaction_hash_count

        return multi_sig_address_state

    @staticmethod
    def create_by_address(address: bytes):
        multi_sig_address_state = MultiSigAddressState()
        multi_sig_address_state._data.address = address
        return multi_sig_address_state

    def update_transaction_hash_count(self, value=1, subtract=False):
        if subtract:
            self._data.transaction_hash_count -= value
        else:
            self._data.transaction_hash_count += value

    def update_multi_sig_spend_count(self, value=1, subtract=False):
        if subtract:
            self._data.multi_sig_spend_count -= value
        else:
            self._data.multi_sig_spend_count += value

    def get_counter_by_name(self, name: bytes):
        return self._counter_by_name[name].get()

    def update_counter_by_name(self, name, value=1, subtract=False):
        self._counter_by_name[name].update(value, subtract)

    def update_balance(self, state_container, value, subtract=False):
        if subtract:
            self._data.balance -= value
        else:
            self._data.balance += value

    @staticmethod
    def get_default(creation_tx_hash, signatories: list, weights: list, threshold: int):
        return MultiSigAddressState.create(creation_tx_hash=creation_tx_hash,
                                           balance=0,
                                           signatories=signatories,
                                           weights=weights,
                                           threshold=threshold,
                                           transaction_hash_count=0)

    @staticmethod
    def address_is_valid(address: bytes) -> bool:
        if address[0:1] != b'\x11':
            return False

        # Warning: Never pass this validation True for Coinbase Address
        if not QRLHelper.addressIsValid(address):
            return False

        return True

    def serialize(self):
        return self._data.SerializeToString()

    def get_weight_by_signatory(self, signatory_address) -> [int, bool]:
        for i in range(len(self.signatories)):
            if self.signatories[i] == signatory_address:
                return self.weights[i], True
        return 0, False

    @staticmethod
    def get_multi_sig_address_state(state: State,
                                    multi_sig_tx):
        try:
            data = state._db.get_raw(multi_sig_tx.addr_from)
            pbdata = qrl_pb2.MultiSigAddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = MultiSigAddressState(pbdata)
            return address_state
        except KeyError:
            return None

    @staticmethod
    def get_multi_sig_address_state_by_address(db,
                                               multi_sig_address: bytes):
        try:
            data = db.get_raw(multi_sig_address)
            pbdata = qrl_pb2.MultiSigAddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = MultiSigAddressState(pbdata)
            return address_state
        except KeyError:
            return None

    @staticmethod
    def get_multi_sig_address_by_shared_key(state: State,
                                            shared_key: bytes):
        tx, _ = TransactionMetadata.get_tx_metadata(state, shared_key)
        if tx is None:
            return None
        return tx.multi_sig_address

    @staticmethod
    def remove_multi_sig_address_state(state: State,
                                       multi_sig_address: bytes,
                                       batch=None):
        try:
            state._db.delete(multi_sig_address, batch)
        except Exception as e:
            logger.warning("Exception ", e)
