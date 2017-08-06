'''
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

In case of a peer requested for a particular hash message,
fails to provide that, then it is considered that peer
doesn't have message of that hash. so peer is removed from
that hash and also the hash is removed from that peer.
Next peer is asked for that same hash message.

Hash has to be removed if it has no peer

TODO:
1. If a peer fails to provide particular message for X number of times
   in a last Y hrs of time. Then that peer is forcefully disconnected.
   IP could be added into block list of that particular peer for couple
   of hours.
'''
from collections import OrderedDict, defaultdict
import configuration as c
from merkle import sha256

class MessageReceipt:
    allowed_types = ['TX', 'ST', 'BK', 'R1']
    def __init__(self):
        self.hash_msg = dict()
        self.hash_type = OrderedDict()
        self.hash_peer = defaultdict(list)
        self.requested_hash = defaultdict(list)
        self.hash_callLater = dict()

    def register(self, msg_hash, msg_obj, msg_type):
        msg_hash = sha256(str(msg_hash))
        self.hash_msg[msg_hash] = msg_obj
        self.hash_type[msg_hash] = msg_type

    def deregister(self, msg_hash, msg_type):
        msg_hash = sha256(str(msg_hash))
        if msg_hash in self.hash_msg:
            del self.hash_msg[msg_hash]
        if msg_hash in self.hash_type:
            del self.hash_type[msg_hash]
        if msg_hash in self.hash_peer:
            del self.hash_peer[msg_hash]
        pass

    def add(self, msg_hash, msg_type, peer):
        if msg_type not in self.allowed_types:
            return

        if len(self.hash_type) == c.message_q_size:
            self.__remove__()

        if msg_hash not in self.hash_type:
            self.hash_type[msg_hash] = msg_type

        self.hash_peer[msg_hash].append(peer)

    def isRequested(self, msg_hash, peer):
        msg_hash = sha256(str(msg_hash))
        if msg_hash in self.requested_hash:
            if peer in self.requested_hash[msg_hash]:
                return True
        return

    def add_to_master(self, msg_hash, msg_type):
        self.hash_type[msg_hash] = msg_type

    def __remove__(self):
        msg_hash, msg_type = self.hash_type.popitem(last=False)

        del self.hash_peer[msg_hash]
        if msg_hash in self.hash_msg:
            del self.hash_msg[msg_hash]

    def remove_hash(self, msg_hash, peer):
        if msg_hash in self.hash_peer:
            if peer in self.hash_peer[msg_hash]:
                self.hash_peer[msg_hash].remove(peer)
                if self.hash_peer[msg_hash]:
                    return
                del self.hash_peer[msg_hash]
                del self.hash_type[msg_hash]

    def contains(self, msg_hash, msg_type):
        if msg_hash in self.hash_msg:
            if msg_hash in self.hash_type:
                if self.hash_type[msg_hash] == msg_type:
                    return True

        return

    def peer_contains_hash(self, msg_hash, msg_type, peer):
        if msg_hash in self.hash_peer:
            if peer in self.hash_peer[msg_hash]:
                if self.hash_type[msg_hash] == msg_type:
                    return True

        return

