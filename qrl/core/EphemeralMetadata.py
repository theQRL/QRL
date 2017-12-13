# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.Transaction import LatticePublicKey
from qrl.generated import qrl_pb2


class LatticePublicKeys:
    def __init__(self, protobuf_lattice_keys=None):
        self._data = protobuf_lattice_keys
        if not self._data:
            self._data = qrl_pb2.LatticePublicKeys()

    @property
    def pbdata(self):
        return self._data

    @property
    def lattice_keys(self):
        return self._data.lattice_keys

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.LatticePublicKeys()
        Parse(json_data, pbdata)
        return LatticePublicKeys(pbdata)

    def to_json(self):
        return MessageToJson(self._data)

    def add_txn(self, lattice_key_txn: LatticePublicKey):
        self.lattice_keys.extend([lattice_key_txn.pbdata])


class MessageLog:
    def __init__(self, protobuf_messagelog=None):
        self._data = protobuf_messagelog
        if not self._data:
            self._data = qrl_pb2.MessageLog()

    @property
    def pbdata(self):
        return self._data

    @property
    def message(self):
        return self._data.message

    @property
    def ttl(self):
        return self._data.ttl

    @property
    def address_from(self):
        return self._data.address_from

    @staticmethod
    def create(message: bytes, ttl: int, address_from: bytes):
        message_log = MessageLog()
        message_log._data.message = message
        message_log._data.ttl = ttl
        message_log._data.address_from = address_from
        return message_log


class EphemeralMetadata:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrl_pb2.EphemeralMetadata()

    @property
    def lattice_key_txn(self):
        return LatticePublicKey(self._data.lattice_key_txn)

    @property
    def xmss_from(self):
        return self._data.xmss_from

    @property
    def xmss_to(self):
        return self._data.xmss_to

    @property
    def sender_expected_prf(self):
        return self._data.sender_expected_prf

    @property
    def receiver_expected_prf(self):
        return self._data.receiver_expected_prf

    @property
    def aes256_symkey(self):
        return self._data.aes256_symkey

    @staticmethod
    def create(lattice_key_txn: LatticePublicKey,
               xmss_from: bytes,
               xmss_to: bytes,
               sender_expected_prf: bytes,
               receiver_expected_prf: bytes,
               aes256_symkey: bytes):
        ephemeral_metadata = EphemeralMetadata()
        ephemeral_metadata._data.lattice_key_txn.MergeFrom(lattice_key_txn.pbdata)
        ephemeral_metadata._data.xmss_from = xmss_from
        ephemeral_metadata._data.xmss_to = xmss_to
        ephemeral_metadata._data.sender_expected_prf = sender_expected_prf
        ephemeral_metadata._data.receiver_expected_prf = receiver_expected_prf
        ephemeral_metadata._data.aes256_symkey = aes256_symkey
        return ephemeral_metadata

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EphemeralMetadata()
        Parse(json_data, pbdata)
        return EphemeralMetadata(pbdata)

    def to_json(self):
        return MessageToJson(self._data)

    def update_prf(self, address):
        if address == self._data.xmss_from:
            self._data.sender_expected_prf = str(int(self.sender_expected_prf) + 2).encode()
        elif address == self._data.xmss_to:
            self._data.receiver_expected_prf = str(int(self.sender_expected_prf) + 2).encode()
        else:
            raise ValueError('Address didnt match either of xmss address')

    def add_message(self, message: bytes, ttl: int, address_from: bytes):
        message_log = MessageLog.create(message, ttl, address_from)
        self._data.message_logs.extend([message_log.pbdata])

    def pop_messages(self):
        output = b''

        for message_log in self._data.message_logs:
            output += bytes(message_log.address_from) + b': ' + bytes(message_log.message) + b'\n'

        if len(output) > 0:
            output = b'Txid: ' + bin2hstr(self.lattice_key_txn.txhash).encode() + \
                     b'\nPublic keys: ' + self.lattice_key_txn.kyber_pk + \
                     b' | ' + self.lattice_key_txn.dilithium_pk + \
                     b'\n\n' + output

        del self._data.message_logs[:]

        return output
