# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from collections import OrderedDict

from typing import Optional

from qrl.core import config
from qrl.core.Message import Message
from qrl.core.MessageRequest import MessageRequest
from qrl.core.txs.CoinBase import CoinBase
from qrl.generated import qrllegacy_pb2
from qrl.generated.qrllegacy_pb2 import LegacyMessage


# FIXME: Refactor / improve
class MessageReceipt(object):
    """
    1> dict Hash to peer
    2> dict peer to Hash

    Remove hash
    1. check peers for that particular hash
    2. remove hash from each peer in peer to hash
    3. Finally remove hash from  hash to peer

    Remove peer
    1. Check hash for that particular peer
    2. remove peer from each hash in hash to peer
    3. remove peer from peer to hash

    In case of a peer requested for a particular hash message, fails to
    provide that, then it is considered that peer doesn't have message
    of that hash. so peer is removed from that hash and also the hash
    is removed from that peer.
    Next peer is asked for that same hash message.

    Hash has to be removed if it has no peer

    TODO:
    1. If a peer fails to provide particular message for X number of times
       in a last Y hrs of time. Then that peer is forcefully disconnected.
       IP could be added into block list of that particular peer for couple
       of hours.

    """

    # TODO: Use enumerations instead of strings to reduce data size
    allowed_types = [LegacyMessage.TX,
                     LegacyMessage.LT,
                     LegacyMessage.EPH,
                     LegacyMessage.BK,
                     LegacyMessage.MT,
                     LegacyMessage.TK,
                     LegacyMessage.TT,
                     LegacyMessage.SL,
                     LegacyMessage.MC,
                     LegacyMessage.MS,
                     LegacyMessage.MV]

    services_arg = {
        ######################
        qrllegacy_pb2.LegacyMessage.VE: 'veData',
        qrllegacy_pb2.LegacyMessage.PL: 'plData',
        qrllegacy_pb2.LegacyMessage.PONG: 'pongData',

        ######################
        qrllegacy_pb2.LegacyMessage.MR: 'mrData',
        qrllegacy_pb2.LegacyMessage.SFM: 'mrData',

        qrllegacy_pb2.LegacyMessage.BK: 'block',
        qrllegacy_pb2.LegacyMessage.FB: 'fbData',
        qrllegacy_pb2.LegacyMessage.PB: 'pbData',

        ############################
        qrllegacy_pb2.LegacyMessage.TX: 'txData',
        qrllegacy_pb2.LegacyMessage.MT: 'mtData',
        qrllegacy_pb2.LegacyMessage.TK: 'tkData',
        qrllegacy_pb2.LegacyMessage.TT: 'ttData',
        qrllegacy_pb2.LegacyMessage.LT: 'ltData',
        qrllegacy_pb2.LegacyMessage.SL: 'slData',

        qrllegacy_pb2.LegacyMessage.EPH: 'ephData',

        qrllegacy_pb2.LegacyMessage.SYNC: 'syncData',

        qrllegacy_pb2.LegacyMessage.MC: 'mcData',
        qrllegacy_pb2.LegacyMessage.MS: 'msData',
        qrllegacy_pb2.LegacyMessage.MV: 'mvData',
    }

    def __init__(self):
        self._hash_msg = OrderedDict()
        self.requested_hash = OrderedDict()

    def register_duplicate(self, msg_hash: bytes):
        self.requested_hash[msg_hash].is_duplicate = True

    def register(self, msg_type, msg_hash: bytes, pbdata):
        """
        Registers an object and type on with msg_hash as key
        There is a limitation on the amount of items (config.dev.message_q_size)
        Containers operate in a FIFO fashion.
        :param msg_hash:
        :param pbdata:
        :param msg_type: Any type!? There is not check on msg_type
        """
        # FIXME: Hash is converted to string
        # FIXME: No check on the validity of the message type
        if len(self._hash_msg) >= config.dev.message_q_size:
            self.__remove__(self._hash_msg)

        message = Message(pbdata, msg_type)

        self._hash_msg[msg_hash] = message

    def get(self, msg_type, msg_hash: bytes) -> Optional[qrllegacy_pb2.LegacyMessage]:
        if not self.contains(msg_hash, msg_type):
            return None

        msg = self._hash_msg[msg_hash].msg
        data = qrllegacy_pb2.LegacyMessage(**{'func_name': msg_type,
                                              self.services_arg[msg_type]: msg})
        return data

    def add_peer(self, msg_hash: bytes, msg_type, peer, data=None):
        # Filter
        if msg_type not in self.allowed_types:
            return

        # Limit amount
        if len(self.requested_hash) >= config.dev.message_q_size:
            self.__remove__(self.requested_hash)

        if msg_hash not in self.requested_hash:
            self.requested_hash[msg_hash] = MessageRequest()

        self.requested_hash[msg_hash].add_peer(msg_type, peer, data)

    def isRequested(self, msg_hash: bytes, peer, block=None):
        if msg_hash in self.requested_hash:
            if peer in self.requested_hash[msg_hash].peers_connection_list:
                return True

        if block:
            if self.block_params(msg_hash, block):
                return True

        self.remove_hash(msg_hash, peer)
        return False

    def block_params(self, msg_hash: bytes, block):
        if msg_hash not in self.requested_hash:
            return False

        params = self.requested_hash[msg_hash].params
        coinbase_tx = CoinBase.from_pbdata(block.transactions[0])
        if coinbase_tx.addr_from != params.stake_selector:
            return False

        if block.block_number != params.block_number:
            return False

        if block.prev_headerhash != params.prev_headerhash:
            return False

        if block.reveal_hash != params.reveal_hash:
            return False

        return True

    def deregister(self, msg_hash: bytes, msg_type):
        if msg_hash in self._hash_msg:
            del self._hash_msg[msg_hash]

    def __remove__(self, myObj):
        myObj.popitem(last=False)

    def remove_hash(self, msg_hash: bytes, peer):
        if msg_hash in self.requested_hash:
            message_request = self.requested_hash[msg_hash]
            if peer in message_request.peers_connection_list:
                message_request.peers_connection_list.remove(peer)
                if not message_request.peers_connection_list:
                    del self.requested_hash[msg_hash]

    def contains(self, msg_hash: bytes, msg_type):
        """
        Indicates if a msg_obj has been registered with that
        msg_hash and matches the msg_type
        :param msg_hash: Hash to use as a key
        :param msg_type: The type of msg to match
        :return: True is the msg_obj is known and matches the msg_type
        """
        if msg_hash in self._hash_msg:
            message = self._hash_msg[msg_hash]
            if message.msg_type == msg_type:
                return True

        return False

    def is_callLater_active(self, msg_hash):
        if msg_hash in self.requested_hash:
            if self.requested_hash[msg_hash].callLater:
                return True

        return False
