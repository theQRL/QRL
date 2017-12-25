# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256
from pyqrllib.kyber import Kyber
from pyqrllib.dilithium import Dilithium

from qrl.generated import qrl_pb2
from qrl.crypto.aes import AES
from qrl.crypto.random_number_generator import RNG
from qrl.core import ntp


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
        if self.msg_id == b'NEW':
            if len(self._data.channel.enc_aes256_symkey) == 0:
                return False
        elif self.msg_id != b'NEW':
            if len(self._data.channel.enc_aes256_symkey):
                return False

        return True

    def to_json(self):
        return MessageToJson(self.pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EncryptedEphemeralMessage()
        Parse(json_data, pbdata)
        return EncryptedEphemeralMessage(pbdata)

    @staticmethod
    def create_channel(ttl: int,
                       ttr: int,
                       addr_from: bytes,
                       kyber_pk: bytes,
                       kyber_sk: bytes,
                       receiver_kyber_pk: bytes,
                       dilithium_pk: bytes,
                       dilithium_sk: bytes,
                       prf512_seed: bytes,
                       data: bytes,
                       nonce: int):

        sender_kyber = Kyber(kyber_pk, kyber_sk)
        sender_kyber.kem_encode(receiver_kyber_pk)
        enc_aes256_symkey = bytes(sender_kyber.getCypherText())
        aes256_symkey = sender_kyber.getMyKey()
        aes = AES(bytes(aes256_symkey))
        sender_dilithium = Dilithium(dilithium_pk, dilithium_sk)

        ephemeral_data = EphemeralChannelPayload.create(addr_from,
                                                        prf512_seed,
                                                        data)

        ephemeral_data.dilithium_sign(b'NEW', ttl, ttr, enc_aes256_symkey, nonce, sender_dilithium)

        encrypted_ephemeral_message = EncryptedEphemeralMessage()

        encrypted_ephemeral_message._data.msg_id = b'NEW'
        encrypted_ephemeral_message._data.ttl = ttl
        encrypted_ephemeral_message._data.ttr = ttr
        encrypted_ephemeral_message._data.channel.enc_aes256_symkey = enc_aes256_symkey
        encrypted_ephemeral_message._data.nonce = nonce
        encrypted_ephemeral_message._data.payload = aes.encrypt(ephemeral_data.to_json().encode())

        return encrypted_ephemeral_message

    @staticmethod
    def create(ttl: int,
               ttr: int,
               addr_from: bytes,
               kyber_pk: bytes,
               kyber_sk: bytes,
               receiver_kyber_pk: bytes,
               prf512_seed: bytes,
               seq: int,
               data: bytes,
               nonce: int):

        sender_kyber = Kyber(kyber_pk, kyber_sk)
        sender_kyber.kem_encode(receiver_kyber_pk)

        aes256_symkey = sender_kyber.getMyKey()
        aes = AES(aes256_symkey)

        ephemeral_data = EphemeralMessagePayload.create(addr_from, data)

        encrypted_ephemeral_message = EncryptedEphemeralMessage()

        encrypted_ephemeral_message._data.msg_id = RNG.generate(prf512_seed, seq)
        encrypted_ephemeral_message._data.ttl = ttl
        encrypted_ephemeral_message._data.ttr = ttr
        encrypted_ephemeral_message._data.nonce = nonce
        encrypted_ephemeral_message._data.payload = aes.encrypt(ephemeral_data.to_json())

        return encrypted_ephemeral_message


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
