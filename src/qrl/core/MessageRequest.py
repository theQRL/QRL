# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core.misc import logger


class MessageRequest:
    def __init__(self):
        self.callLater = None
        self.msg_type = None
        self.peers_connection_list = []
        self.already_requested_peers = []
        self.params = None
        self.is_duplicate = False

    def add_peer(self, msg_type, peer, params=None):
        self.msg_type = msg_type
        self.peers_connection_list.append(peer)
        self.params = params

    def validate(self, data):
        try:
            for key in self.params.keys():
                if self.params[key] != data[key]:
                    return False
            return True
        except KeyError as k:
            logger.error('Params Keys %s', self.params.keys())
            logger.error('Data Keys %s', data.keys())
            logger.error('Key Not found %s ', k)
        except AttributeError as k:
            logger.error('MessageRequest.params was not initialized before calling validate()')

        return False
