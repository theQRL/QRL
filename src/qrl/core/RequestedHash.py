# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from collections import OrderedDict, defaultdict

from qrl.core.MessageRequest import MessageRequest
from qrl.core import config


class RequestedHash:
    def __init__(self):
        self._msg_hash_msg_request = OrderedDict()
        self._peer_to_msg_hash = defaultdict(list)

    def remove_peer_from_msg_hash(self, msg_hash, peer):
        if not self.does_message_hash_exist(msg_hash):
            return

        self._msg_hash_msg_request[msg_hash].remove_peer(peer)
        if self._msg_hash_msg_request[msg_hash].total_peers() == 0:
            self.remove_msg_hash(msg_hash)

    def remove_msg_hash_from_peer(self, msg_hash, peer):
        if peer not in self._peer_to_msg_hash:
            return
        if msg_hash not in self._peer_to_msg_hash[peer]:
            return
        self._peer_to_msg_hash[peer].remove(msg_hash)

    def remove_peer(self, peer):
        if peer not in self._peer_to_msg_hash:
            return
        msg_hashes = list(self._peer_to_msg_hash[peer])
        for msg_hash in msg_hashes:
            self.remove_peer_from_msg_hash(msg_hash, peer)
        del self._peer_to_msg_hash[peer]

    def add_msg_hash(self, msg_hash, msg_type, peer, data=None):
        if not self.does_message_hash_exist(msg_hash):
            self._msg_hash_msg_request[msg_hash] = MessageRequest()

        self._msg_hash_msg_request[msg_hash].add_peer(msg_type, peer, data)

    def add_msg_hash_and_peer(self, msg_hash, msg_type, peer, data=None):
        # Remove msg_hash if it already exists in peer_to_msg_hash before adding
        # to avoid early pop
        if msg_hash in self._peer_to_msg_hash[peer]:
            self._peer_to_msg_hash[peer].remove(msg_hash)

        self._peer_to_msg_hash[peer].append(msg_hash)

        if len(self._peer_to_msg_hash[peer]) > config.dev.message_q_size:
            req_msg_hash = self._peer_to_msg_hash[peer].pop(0)
            self.remove_peer_from_msg_hash(req_msg_hash, peer)

        self.add_msg_hash(msg_hash, msg_type, peer, data)

    def remove_msg_hash(self, msg_hash):
        if not self.does_message_hash_exist(msg_hash):
            return

        message_request = self._msg_hash_msg_request[msg_hash]
        if message_request is None:
            return

        if message_request.callLater is not None and message_request.callLater.active():
            message_request.callLater.cancel()

        del self._msg_hash_msg_request[msg_hash]

        for peer in self._peer_to_msg_hash:
            if msg_hash in self._peer_to_msg_hash[peer]:
                self._peer_to_msg_hash[peer].remove(msg_hash)

    def get_msg_request(self, msg_hash):
        if not self.does_message_hash_exist(msg_hash):
            return None
        return self._msg_hash_msg_request[msg_hash]

    def does_message_hash_exist(self, msg_hash):
        return msg_hash in self._msg_hash_msg_request
