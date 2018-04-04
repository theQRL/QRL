# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.generated import qrllegacy_pb2


class P2PBaseObserver(object):
    def __init__(self):
        pass

    @staticmethod
    def _validate_message(message: qrllegacy_pb2.LegacyMessage, expected_func_name):
        if message.func_name != expected_func_name:
            raise ValueError("Invalid func_name")

    def new_channel(self, channel):
        pass
