# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from copy import deepcopy
from collections import defaultdict

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
    def pubhashes(self):
        return self._data.pubhashes

    @property
    def transaction_hashes(self):
        return self._data.transaction_hashes

    @staticmethod
    def create(address: bytes, nonce: int, balance: int, pubhashes: list, tokens: dict):
        address_state = AddressState()

        address_state._data.address = address
        address_state._data.nonce = nonce
        address_state._data.balance = balance
        address_state._data.pubhashes.extend(pubhashes)

        for token_txhash in tokens:
            address_state.tokens[token_txhash] = tokens[token_txhash]

        return address_state

    def increase_nonce(self):
        self._data.nonce += 1
