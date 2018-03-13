# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse

from qrl.core.misc import ntp
from qrl.core import config
from qrl.generated import qrl_pb2


class PeerInfo:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrl_pb2.PeerInfo()

    @property
    def pbdata(self):
        return self._data

    @property
    def peer_ip(self):
        return self._data.peer_ip

    @property
    def port(self):
        return self._data.port

    @property
    def banned_timestamp(self):
        return self._data.banned_timestamp

    @property
    def credibility(self):
        return self._data.credibility

    @property
    def last_connections_timestamp(self):
        return self._data.last_connections_timestamp

    @staticmethod
    def create(peer_ip: bytes, port: int):
        peer = PeerInfo()
        peer._data.peer_ip = peer_ip
        peer._data.port = port
        peer._data.credibility = 0  # TODO: To be used later, to assign higher points to peer with good behavior
        peer._data.extend([ntp.getTime()])

        return peer

    def update_last_connections_timestamp(self):
        self._data.last_connections_timestamp.extend([ntp.getTime()])
        if len(self._data.last_connections_timestamp) > config.user.monitor_last_x_connection_time:
            del self._data.last_connections_timestamp[0]

    def is_frequent_disconnector(self) -> bool:
        if len(self._data.last_connections_timestamp) < config.user.monitor_last_x_connection_time:
            return False

        timestamp_diff = self._data.last_connections_timestamp[-1] - self._data.last_connections_timestamp[0]

        if timestamp_diff < config.user.frequent_disconnect_threshold:
            return True

        return False

    def is_banned(self) -> bool:
        if self.banned_timestamp > ntp.getTime():
            return True

        return False

    def ban(self):
        self._data.banned_timestamp = ntp.getTime() + (config.user.ban_minutes * 60)

    def to_json(self):
        return MessageToJson(self.pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.PeerInfo()
        Parse(json_data, pbdata)
        return PeerInfo(pbdata)
