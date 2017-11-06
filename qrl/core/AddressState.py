# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict

from google.protobuf.json_format import MessageToJson, Parse

from qrl.core import config
from qrl.core.Transaction import CoinBase, Transaction
from qrl.core.Transaction_subtypes import TX_SUBTYPE_TX
from qrl.core.BlockHeader import BlockHeader
from qrl.crypto.misc import sha256, merkle_tx_hash
from qrl.crypto.xmss import XMSS
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
    def nonce(self):
        return self._data.nonce

    @property
    def balance(self):
        return self._data.balance

    @property
    def pubhashes(self):
        return self._data.pubhashes

    @staticmethod
    def create(address: bytes, nonce: int, balance: int, pubhashes: list):
        address_state = AddressState()

        address_state._data.address = address
        address_state._data.nonce = nonce
        address_state._data.balance = balance
        address_state._data.pubhashes.extend(pubhashes)

        return address_state
