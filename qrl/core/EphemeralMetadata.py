# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from google.protobuf.json_format import MessageToJson, Parse

from qrl.core.misc import ntp
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.generated import qrl_pb2


class EphemeralMetadata:
    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrl_pb2.EphemeralMetadata()

    @property
    def pbdata(self):
        return self._data

    @property
    def encrypted_ephemeral_message_list(self):
        return self._data.encrypted_ephemeral_message_list

    def add(self, encrypted_ephemeral):
        self.update()
        target_hash = encrypted_ephemeral.get_message_hash()

        for raw_encrypted_ephemeral in self.encrypted_ephemeral_message_list:
            if EncryptedEphemeralMessage(raw_encrypted_ephemeral).get_message_hash() == target_hash:
                return
        self._data.encrypted_ephemeral_message_list.extend([encrypted_ephemeral.pbdata])

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.EphemeralMetadata()
        Parse(json_data, pbdata)
        return EphemeralMetadata(pbdata)

    def to_json(self):
        return MessageToJson(self._data)

    def update(self):
        total_len = len(self.encrypted_ephemeral_message_list)

        for index in range(total_len):
            encrypted_ephemeral = self._data.encrypted_ephemeral_message_list[index]
            if ntp.getTime() > encrypted_ephemeral.ttl:
                del self._data.encrypted_ephemeral_message_list[index]
                index -= 1
                continue
