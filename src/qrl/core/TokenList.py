# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from google.protobuf.json_format import MessageToJson, Parse

from qrl.generated import qrl_pb2


class TokenList(object):
    """
    Maintains the list of tokens in the network.
    """
    def __init__(self, protobuf_data=None):
        self._data = protobuf_data
        if protobuf_data is None:
            self._data = qrl_pb2.TokenList()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf TokenList object
        :rtype: qrl_pb2.TokenList
        """
        return self._data

    @property
    def token_txhash(self):
        return self._data.token_txhash

    @staticmethod
    def create(token_txhashes: list):
        token_list = TokenList()

        token_list._data.token_txhash.extend(token_txhashes)

        return token_list

    def update(self, token_txhashes: list):
        self.token_txhash.extend(token_txhashes)

    def to_json(self):
        return MessageToJson(self._data, sort_keys=True)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.TokenList()
        Parse(json_data, pbdata)
        return TokenList(pbdata)
