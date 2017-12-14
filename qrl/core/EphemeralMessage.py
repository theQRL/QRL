# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256

from typing import Optional
import simplejson as json
from qrl.core import logger
from qrl.core.Transaction import LatticePublicKey
from qrl.generated import qrl_pb2
from qrl.crypto.xmss import XMSS


class EncryptedEphemeralMessage:
    def __init__(self, protobuf_enc_ephemeral_message=None):
        self._data = protobuf_enc_ephemeral_message
        if not protobuf_enc_ephemeral_message:
            self._data = qrl_pb2.EncryptedEphemeralMessage()

    @property
    def aes256_symkey(self):
        return self._data.aes256_symkey

    @property
    def prf512_seed(self):
        return self._data.prf512_seed

    @property
    def xmss_address(self):
        return self._data.xmss_address

    @property
    def xmss_pk(self):
        return self._data.xmss_pk

    @property
    def xmss_signature(self):
        return self._data.xmss_signature

    @staticmethod
    def create(aes256_symkey: bytes, prf512_seed: bytes, xmss: XMSS, lattice_key: bytes):
        encrypted_ephemeral_message = EncryptedEphemeralMessage()
        encrypted_ephemeral_message._data.aes256_symkey = EphemeralMessage.lattice_encrypt(data=aes256_symkey,
                                                                                           key=lattice_key)
        encrypted_ephemeral_message._data.prf512_seed = EphemeralMessage.aes256_encrypt(data=prf512_seed,
                                                                                        key=aes256_symkey)
        encrypted_ephemeral_message._data.xmss_address = EphemeralMessage.aes256_encrypt(data=xmss.get_address(),
                                                                                         key=aes256_symkey)
        encrypted_ephemeral_message._data.xmss_pk = EphemeralMessage.aes256_encrypt(data=xmss.pk(),
                                                                                    key=aes256_symkey)
        encrypted_ephemeral_message._data.xmss_signature = EphemeralMessage.aes256_encrypt(data=xmss.SIGN(aes256_symkey + prf512_seed),
                                                                                           key=aes256_symkey)

        return encrypted_ephemeral_message

    def to_json(self):
        return MessageToJson(self._data)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EncryptedEphemeralMessage()
        Parse(json_data, pbdata)
        return EncryptedEphemeralMessage(pbdata)


class DecryptedEphemeralMessage:
    def __init__(self):
        self._aes256_symkey = None
        self._prf512_seed = None
        self._lattice_key_txn = None
        self._xmss_from = None
        self._xmss_to = None
        self._xmss_pk = None
        self._xmss_signature = None
        self._message = None

    @property
    def aes256_symkey(self):
        return self._aes256_symkey

    @property
    def prf512_seed(self):
        return self._prf512_seed

    @property
    def lattice_key_txn(self):
        return self._lattice_key_txn

    @property
    def xmss_from(self):
        return self._xmss_from

    @property
    def xmss_to(self):
        return self._xmss_to

    @property
    def xmss_pk(self):
        return self._xmss_pk

    @property
    def xmss_signature(self):
        return self._xmss_signature

    @property
    def message(self):
        return self._message

    @staticmethod
    def create(aes256_symkey: bytes,
               prf512_seed: bytes,
               lattice_key_txn: LatticePublicKey,
               xmss_from: bytes,
               xmss_to: bytes,
               xmss_pk: bytes,
               xmss_signature: bytes,
               ):
        decrypted_ephemeral_message = DecryptedEphemeralMessage()
        decrypted_ephemeral_message._aes256_symkey = aes256_symkey
        decrypted_ephemeral_message._prf512_seed = prf512_seed
        decrypted_ephemeral_message._lattice_key_txn = lattice_key_txn
        decrypted_ephemeral_message._xmss_from = xmss_from
        decrypted_ephemeral_message._xmss_to = xmss_to
        decrypted_ephemeral_message._xmss_pk = xmss_pk
        decrypted_ephemeral_message._xmss_signature = xmss_signature
        return decrypted_ephemeral_message


class EphemeralMessage:
    """
    Ephemeral Channel Request is performed before sending
    any ephemeral message
    """
    def __init__(self, protobuf_ephemeral_message=None):
        self._data = protobuf_ephemeral_message
        if protobuf_ephemeral_message is None:
            self._data = qrl_pb2.EphemeralMessage()

        self._decrypted_ephemeral_message = DecryptedEphemeralMessage()

    @property
    def msg_id(self):
        return self._data.msg_id

    @property
    def ttl(self):
        return self._data.ttl

    @property
    def active(self):
        return self._data.active

    @property
    def message(self):
        return self._data.message

    @property
    def decrypted_message(self):
        return self._decrypted_ephemeral_message.message

    @property
    def aes256_symkey(self):
        return self._decrypted_ephemeral_message.aes256_symkey

    @property
    def prf512_seed(self):
        return self._decrypted_ephemeral_message.prf512_seed

    @property
    def lattice_key_txn(self):
        return self._decrypted_ephemeral_message.lattice_key_txn

    @property
    def xmss_from(self):
        return self._decrypted_ephemeral_message.xmss_from

    @property
    def xmss_to(self):
        return self._decrypted_ephemeral_message.xmss_to

    @property
    def xmss_pk(self):
        return self._decrypted_ephemeral_message.xmss_pk

    @property
    def xmss_signature(self):
        return self._decrypted_ephemeral_message.xmss_signature

    @staticmethod  # move to crypto
    def lattice_encrypt(data: bytes, key: bytes) -> bytes:
        key = key[-1::-1]
        encrypted_data = key + data
        return encrypted_data

    @staticmethod
    def lattice_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        if not encrypted_data.startswith(key[-1::-1]):  # Place holder for lattice decryption, ignore -1::-1
            raise ValueError('Unable to Decrypt using Lattice Key')

        decrypted_data = encrypted_data[len(key):]

        return decrypted_data

    @staticmethod
    def aes256_encrypt(data: bytes, key: bytes) -> bytes:
        encrypted_data = key + data
        return encrypted_data

    @staticmethod
    def aes256_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        if not encrypted_data.startswith(key):
            raise ValueError('Unable to Decrypt using AES256 key')

        decrypted_data = encrypted_data[len(key):]

        return decrypted_data

    @staticmethod
    def create_message(msg_id: bytes,
                       ttl: int,
                       active: int,
                       message: bytes,
                       aes256_symkey: bytes):
        ephemeral_message = EphemeralMessage()
        ephemeral_message._data.msg_id = msg_id
        ephemeral_message._data.ttl = ttl
        ephemeral_message._data.active = active
        data = dict()
        data['message'] = message
        ephemeral_message._data.message = EphemeralMessage.aes256_encrypt(data=json.dumps(data).encode(),
                                                                          key=aes256_symkey)
        ephemeral_message._decrypted_ephemeral_message = DecryptedEphemeralMessage()
        ephemeral_message._decrypted_ephemeral_message._message = message
        return ephemeral_message

    @staticmethod
    def create_channel_request(ttl: int,
                               active: int,
                               lattice_key_txn: LatticePublicKey,
                               aes256_symkey: bytes,
                               prf512_seed: bytes,
                               address_to: bytes,
                               xmss: XMSS):
        ephemeral_message = EphemeralMessage()
        ephemeral_message._data.msg_id = b'NEW'
        ephemeral_message._data.ttl = ttl
        ephemeral_message._data.active = active

        encrypted_ephemeral_message = EncryptedEphemeralMessage.create(aes256_symkey,
                                                                       prf512_seed,
                                                                       xmss,
                                                                       lattice_key_txn.kyber_pk)

        message = EphemeralMessage.lattice_encrypt(data=encrypted_ephemeral_message.to_json().encode(),
                                                   key=lattice_key_txn.kyber_pk)

        ephemeral_message._decrypted_ephemeral_message._lattice_key_txn = lattice_key_txn
        ephemeral_message._decrypted_ephemeral_message._aes256_symkey = aes256_symkey
        ephemeral_message._decrypted_ephemeral_message._prf512_seed = prf512_seed
        ephemeral_message._decrypted_ephemeral_message._xmss_from = xmss.get_address()
        ephemeral_message._decrypted_ephemeral_message._xmss_to = address_to
        ephemeral_message._decrypted_ephemeral_message._xmss_pk = xmss.pk()
        ephemeral_message._decrypted_ephemeral_message._xmss_signature = EncryptedEphemeralMessage.xmss_signature
        ephemeral_message._data.message = message

        return ephemeral_message

    @staticmethod
    def from_pbdata(pbdata: qrl_pb2.EphemeralMessage):
        ephemeral_message = EphemeralMessage(pbdata)
        return ephemeral_message

    def verify(self, lattice_keys: list, xmss_address: bytes) -> bool:
        if self.msg_id == b'NEW':
            if not self.decrypt_channel_request_msg(lattice_keys, xmss_address):
                return False
            return self.verify_channel_request()

        return True

    def decrypt_channel_request_msg(self, lattice_keys: list, xmss_address: bytes):
        for raw_lattice_key in lattice_keys:
            lattice_key_txn = LatticePublicKey(raw_lattice_key)
            logger.info('Lattice Keys --> %s', lattice_keys)
            try:
                decrypted_msg = self.lattice_decrypt(self.message, lattice_key_txn.kyber_pk).decode()
                encrypted_ephemeral_message = EncryptedEphemeralMessage.from_json(decrypted_msg)

                decrypted_msg = dict()
                decrypted_msg['aes256_symkey'] = self.lattice_decrypt(encrypted_ephemeral_message.aes256_symkey,
                                                                      lattice_key_txn.kyber_pk)
                aes256_symkey = decrypted_msg['aes256_symkey']
                decrypted_msg['prf512_seed'] = self.aes256_decrypt(encrypted_ephemeral_message.prf512_seed, aes256_symkey)
                decrypted_msg['xmss_address'] = self.aes256_decrypt(encrypted_ephemeral_message.xmss_address, aes256_symkey)
                decrypted_msg['xmss_pk'] = self.aes256_decrypt(encrypted_ephemeral_message.xmss_pk, aes256_symkey)
                decrypted_msg['xmss_signature'] = self.aes256_decrypt(encrypted_ephemeral_message.xmss_signature,
                                                                      aes256_symkey)

                self._decrypted_ephemeral_message = DecryptedEphemeralMessage.create(
                                                    aes256_symkey=decrypted_msg['aes256_symkey'],
                                                    prf512_seed=decrypted_msg['prf512_seed'],
                                                    lattice_key_txn=lattice_key_txn,
                                                    xmss_from=decrypted_msg['xmss_address'],
                                                    xmss_to=xmss_address,
                                                    xmss_pk=decrypted_msg['xmss_pk'],
                                                    xmss_signature=decrypted_msg['xmss_signature'],
                                                    )
                return True
            except ValueError:
                pass
            except Exception as e:
                logger.error('Unexpected Exception while Decrypting channel request msg')
                logger.error(e)

        return False

    def decrypt_ephemeral_msg(self, symmetric_key) -> Optional[dict]:
        try:
            decrypted_message = self.aes256_decrypt(self.message, symmetric_key)
            decrypted_message = json.loads(decrypted_message)
            decrypted_message['message'] = decrypted_message['message'].encode()
            return decrypted_message
        except ValueError:
            pass
        except Exception as e:
            logger.error('Unexpected Exception while decrypting ephemeral message')
            logger.error(e)

        return None

    def verify_channel_request(self) -> bool:
        xmss_signed_message = self._decrypted_ephemeral_message.aes256_symkey + \
                              self._decrypted_ephemeral_message.prf512_seed

        if not XMSS.VERIFY(message=xmss_signed_message,
                           signature=self._decrypted_ephemeral_message.xmss_signature,
                           pk=self._decrypted_ephemeral_message.xmss_pk):
            logger.warning('XMSS Verify failed for Ephemeral Channel Request')
            return False

        return True

    def verify_message(self, aes_key: bytes) -> bool:
        try:
            message = EphemeralMessage.aes256_decrypt(self.message, aes_key)
            message = json.loads(message.decode())
            self._decrypted_ephemeral_message = DecryptedEphemeralMessage()
            self._decrypted_ephemeral_message._message = message['message'].encode()
            return True
        except ValueError:
            pass
        except Exception as e:
            logger.error('Unexpected Exception while Decrypting channel request msg')
            logger.error(e)

        return False

    def to_json(self):
        return MessageToJson(self._data)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EphemeralMessage()
        Parse(json_data, pbdata)
        return EphemeralMessage(pbdata)

    def get_message_hash(self) -> bytes:
        return bytes(sha2_256(bytes(self.msg_id) +
                              str(self.ttl).encode() +
                              str(self.active).encode() +
                              bytes(self.message)))
