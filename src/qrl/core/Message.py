# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class Message:
    def __init__(self, pbdata, msg_type):
        self.msg = pbdata
        self.msg_type = msg_type

    def add_peer(self, msg_type):
        self.msg_type = msg_type
        return self
