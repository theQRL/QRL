# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256

from qrl.generated import qrl_pb2
from qrl.core.misc import ntp


class EncryptedEphemeralMessage(object):
    def __init__(self, protobuf_transaction=None):
        self._data = protobuf_transaction
        if not self._data:
            self._data = qrl_pb2.EncryptedEphemeralMessage()

    def get_message_hash(self):
        msg_hash = (
                     str(self._data.msg_id).encode() +
                     str(self._data.ttl).encode() +
                     str(self._data.ttr).encode() +
                     str(self._data.nonce).encode() +
                     self._data.channel.enc_aes256_symkey +
                     self._data.payload
                   )
        return bytes(sha2_256(msg_hash))

    @property
    def pbdata(self):
        return self._data

    @property
    def msg_id(self):
        return self._data.msg_id

    @property
    def ttl(self):
        return self._data.ttl

    @property
    def ttr(self):
        return self._data.ttr

    @property
    def enc_aes256_symkey(self):
        return self._data.channel.enc_aes256_symkey

    @property
    def nonce(self):
        return self._data.nonce

    @property
    def payload(self):
        return self._data.payload

    def validate(self):
        if self.ttl < self.ttr:
            return False
        if ntp.getTime() > self.ttl:
            return False

        return True

    def to_json(self):
        return MessageToJson(self.pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EncryptedEphemeralMessage()
        Parse(json_data, pbdata)
        return EncryptedEphemeralMessage(pbdata)
