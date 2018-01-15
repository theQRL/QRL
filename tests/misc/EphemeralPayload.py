# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256

from qrl.generated import qrl_pb2


class EphemeralChannelPayload:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not self._data:
            self._data = qrl_pb2.EphemeralChannelPayload()

    @property
    def pbdata(self):
        return self._data

    @property
    def prf512_seed(self):
        return self._data.prf512_seed

    @property
    def dilithium_signature(self):
        return self._data.dilithium_signature

    @property
    def addr_from(self):
        return self._data.addr_from

    @property
    def data(self):
        return self._data.data

    @staticmethod
    def create(addr_from, prf512_seed, data):
        ephemeral_channel_payload = EphemeralChannelPayload()
        ephemeral_channel_payload._data.addr_from = addr_from
        ephemeral_channel_payload._data.prf512_seed = prf512_seed
        ephemeral_channel_payload._data.data = data

        return ephemeral_channel_payload

    def dilithium_sign(self, msg_id, ttl, ttr, enc_aes256_symkey, nonce, sender_dilithium):
        ephemeral_hash = (
                           msg_id +
                           str(ttl).encode() +
                           str(ttr).encode() +
                           enc_aes256_symkey +
                           self.addr_from +
                           str(self.prf512_seed).encode() +
                           str(nonce).encode() +
                           self.data
                         )

        self._data.dilithium_signature = bytes(sender_dilithium.sign(bytes(sha2_256(ephemeral_hash))))

    def to_json(self):
        return MessageToJson(self.pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EphemeralChannelPayload()
        Parse(json_data, pbdata)
        return EphemeralChannelPayload(pbdata)


class EphemeralMessagePayload:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not self._data:
            self._data = qrl_pb2.EphemeralMessagePayload()

    @property
    def pbdata(self):
        return self._data

    @property
    def addr_from(self):
        return self._data.addr_from

    @property
    def data(self):
        return self._data.data

    @staticmethod
    def create(addr_from, data):
        ephemeral_channel_payload = EphemeralMessagePayload()
        ephemeral_channel_payload._data.addr_from = addr_from
        ephemeral_channel_payload._data.data = data

        return ephemeral_channel_payload

    def to_json(self):
        return MessageToJson(self.pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EphemeralMessagePayload()
        Parse(json_data, pbdata)
        return EphemeralMessagePayload(pbdata)
