# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from google.protobuf.json_format import MessageToJson, Parse

from qrl.generated import qrl_pb2
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction


class TokenMetadata(object):
    def __init__(self, protobuf_data=None):
        self._data = protobuf_data
        if protobuf_data is None:
            self._data = qrl_pb2.TokenMetadata()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf TokenMetadata object
        :rtype: qrl_pb2.TokenMetadata
        """
        return self._data

    @property
    def token_txhash(self):
        return self._data.token_txhash

    @property
    def transfer_token_tx_hashes(self):
        return self._data.transfer_token_tx_hashes

    @staticmethod
    def create(token_txhash: bytes, transfer_token_txhashes: list):
        token_metadata = TokenMetadata()

        token_metadata._data.token_txhash = token_txhash

        token_metadata.update(transfer_token_txhashes)

        return token_metadata

    def update(self, transfer_token_txhashes: list):
        for transfer_token_txhash in transfer_token_txhashes:
            self._data.transfer_token_tx_hashes.extend([transfer_token_txhash])

    def remove(self, transfer_token_txhash: bytes):
        i = 0
        while i < len(self._data.transfer_token_tx_hashes):
            if self._data.transfer_token_tx_hashes[i] == transfer_token_txhash:
                del self._data.transfer_token_tx_hashes[i]
                return
            i += 1

    def to_json(self):
        return MessageToJson(self._data, sort_keys=True)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.TokenMetadata()
        Parse(json_data, pbdata)
        return TokenMetadata(pbdata)

    def serialize(self) -> str:
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrl_pb2.TokenMetadata()
        pbdata.ParseFromString(bytes(data))
        return TokenMetadata(pbdata)

    @staticmethod
    def get_token_metadata(state: State, token_txhash: bytes):
        try:
            data = state._db.get_raw(b'token_' + token_txhash)
            return TokenMetadata.deserialize(data)
        except KeyError:
            pass
        except Exception as e:
            logger.error('[get_token_metadata] %s', e)

        return None

    @staticmethod
    def update_token_metadata(state: State, transfer_token: TransferTokenTransaction, batch):
        token_metadata = TokenMetadata.get_token_metadata(state, transfer_token.token_txhash)
        token_metadata.update([transfer_token.txhash])
        state._db.put_raw(b'token_' + transfer_token.token_txhash,
                          token_metadata.serialize(),
                          batch)

    @staticmethod
    def create_token_metadata(state: State, token: TokenTransaction, batch):
        token_metadata = TokenMetadata.create(token_txhash=token.txhash, transfer_token_txhashes=[token.txhash])
        state._db.put_raw(b'token_' + token.txhash,
                          token_metadata.serialize(),
                          batch)

    @staticmethod
    def remove_transfer_token_metadata(state: State, transfer_token: TransferTokenTransaction, batch):
        token_metadata = TokenMetadata.get_token_metadata(state, transfer_token.token_txhash)
        token_metadata.remove(transfer_token.txhash)
        state._db.put_raw(b'token_' + transfer_token.token_txhash,
                          token_metadata.serialize(),
                          batch)

    @staticmethod
    def remove_token_metadata(state: State, token: TokenTransaction, batch):
        state._db.delete(b'token_' + token.txhash, batch)
