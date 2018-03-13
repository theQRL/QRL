# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse

from qrl.core.PeerInfo import PeerInfo
from qrl.generated import qrl_pb2


class Peers:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrl_pb2.Peers()

    @property
    def pbdata(self):
        return self._data

    @property
    def peer_info_list(self):
        return self._data.peer_info_list

    def add_peer(self, peer: PeerInfo):
        self._data.peer.extend([peer.pbdata])

    def to_json(self):
        return MessageToJson(self.pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Peers()
        Parse(json_data, pbdata)
        return Peers(pbdata)
