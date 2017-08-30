# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from collections import OrderedDict, defaultdict

from qrl.core import config
from qrl.crypto.misc import sha256


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
    allowed_types = ['TX', 'ST', 'BK', 'R1']

    def __init__(self):
        # Keep three dicts using hash as a key
        self.hash_msg = dict()
        self.hash_type = OrderedDict()
        self.hash_peer = defaultdict(list)

        # TODO: Check if this is deprecated
        #self.requested_hash = defaultdict(list)
        #self.hash_callLater = dict()

    def register(self, msg_hash, msg_obj, msg_type):
        """
        Registers an object and type on with msg_hash as key
        There is a limitation on the amount of items (config.dev.message_q_size)
        Containers operate in a FIFO fashion.
        :param msg_hash:
        :param msg_obj:
        :param msg_type: Any type!? There is not check on msg_type
        """
        # FIXME: Hash is converted to string
        # FIXME: No check on the validity of the message type
        if len(self.hash_type) >= config.dev.message_q_size:
            self.__remove__()

        msg_hash = sha256(str(msg_hash))
        self.hash_type[msg_hash] = msg_type
        self.hash_msg[msg_hash] = msg_obj

    def deregister(self, msg_hash, msg_type):
        # FIXME: Hash is converted to string
        msg_hash = sha256(str(msg_hash))

        if msg_hash in self.hash_msg:
            del self.hash_msg[msg_hash]
        if msg_hash in self.hash_type:
            del self.hash_type[msg_hash]
        if msg_hash in self.hash_peer:
            del self.hash_peer[msg_hash]

    def add_peer(self, msg_hash, msg_type, peer):
        # Filter
        if msg_type not in self.allowed_types:
            return

        # Limit amount
        if len(self.hash_type) >= config.dev.message_q_size:
            self.__remove__()

        # Register type
        if msg_hash not in self.hash_type:
            self.hash_type[msg_hash] = msg_type

        self.hash_peer[msg_hash].append(peer)

    # TODO: confirm this is deprecated
    # def isRequested(self, msg_hash, peer):
    #     msg_hash = sha256(str(msg_hash))
    #     if msg_hash in self.requested_hash:
    #         if peer in self.requested_hash[msg_hash]:
    #             return True
    #     return False

    # TODO: confirm this is deprecated
    # def add_to_master(self, msg_hash, msg_type):
    #     self.hash_type[msg_hash] = msg_type

    def __remove__(self):
        msg_hash, msg_type = self.hash_type.popitem(last=False)

        if msg_hash in self.hash_peer:
            del self.hash_peer[msg_hash]

        if msg_hash in self.hash_msg:
            del self.hash_msg[msg_hash]

    # TODO: confirm this is deprecated
    # def remove_hash(self, msg_hash, peer):
    #     if msg_hash in self.hash_peer:
    #         if peer in self.hash_peer[msg_hash]:
    #             self.hash_peer[msg_hash].remove(peer)
    #             if self.hash_peer[msg_hash]:
    #                 return
    #             del self.hash_peer[msg_hash]
    #             del self.hash_type[msg_hash]

    def contains(self, msg_hash, msg_type):
        """
        Indicates if a msg_obj has been registered with that
        msg_hash and matches the msg_type
        :param msg_hash: Hash to use as a key
        :param msg_type: The type of msg to match
        :return: True is the msg_obj is known and matches the msg_type
        """
        if msg_hash in self.hash_msg:
            if msg_hash in self.hash_type:
                if self.hash_type[msg_hash] == msg_type:
                    return True

        return False

    def peer_contains_hash(self, msg_hash, msg_type, peer):
        if msg_hash in self.hash_peer:
            if peer in self.hash_peer[msg_hash]:
                if self.hash_type[msg_hash] == msg_type:
                    return True

        return False
