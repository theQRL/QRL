# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class Message:
    """
    This class is merely a container for MessageReceipt, which is a hash map
    that looks like this: {"txhash/blockheaderhash": Message(msg_type=TX/BK,
    pbdata=actual_pbdata_of_block_or_tx}
    """

    def __init__(self, pbdata, msg_type):
        self.msg = pbdata
        self.msg_type = msg_type

    def add_peer(self, msg_type):
        self.msg_type = msg_type
        return self
