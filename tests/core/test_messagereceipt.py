# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import ipaddress
from unittest import TestCase

from pyqrllib.pyqrllib import str2bin
from qrl.core import config
from qrl.core.misc import logger
from qrl.core.messagereceipt import MessageReceipt
from qrl.generated.qrllegacy_pb2 import LegacyMessage

logger.initialize_default()


class TestMessageReceipt(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMessageReceipt, self).__init__(*args, **kwargs)

    def test_create(self):
        mr = MessageReceipt()
        self.assertIsNotNone(mr)
        self.assertEqual(mr.allowed_types, [LegacyMessage.TX,
                                            LegacyMessage.LT,
                                            LegacyMessage.EPH,
                                            LegacyMessage.BK,
                                            LegacyMessage.MT,
                                            LegacyMessage.TK,
                                            LegacyMessage.TT,
                                            LegacyMessage.SL,
                                            LegacyMessage.MC,
                                            LegacyMessage.MS,
                                            LegacyMessage.MV])

    def test_register(self):
        mr = MessageReceipt()

        msg_hash = str2bin("asdf")
        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]

        mr.register(msg_type, msg_hash, msg_obj)

    def test_add_contains_remove(self):
        mr = MessageReceipt()

        msg_hash = str2bin("hash_valid")
        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]
        peer = '127.0.0.1'

        mr.register(msg_type, msg_hash, msg_obj)
        mr.add_peer(msg_hash, msg_type, peer)

        self.assertTrue(mr.contains(msg_hash, msg_type))
        self.assertFalse(mr.contains(b'hash_invalid', msg_type))

    def test_add_peer(self):
        mr = MessageReceipt()

        msg_type = mr.allowed_types[0]
        initial_ip_addr = '127.0.0.1'
        peer = ipaddress.ip_address(initial_ip_addr)

        # Keep adding msg_hash upto maximum size limit
        for i in range(config.dev.message_q_size):
            msg_hash = str(i).encode()
            mr.add_peer(msg_hash, msg_type, peer)
            self.assertEqual(len(mr._requested_hash._msg_hash_msg_request), i + 1)
            self.assertEqual(len(mr._requested_hash._msg_hash_msg_request[msg_hash].peers_connection_list), 1)
            self.assertEqual(mr._requested_hash._msg_hash_msg_request[msg_hash].peers_connection_list[0], peer)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash), 1)
        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request), config.dev.message_q_size)

        self.assertIn(peer, mr._requested_hash._peer_to_msg_hash)
        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), config.dev.message_q_size)
        self.assertEqual(b'0', mr._requested_hash._peer_to_msg_hash[peer][0])

        # adding new msg_hash beyond size limit
        msg_hash = str(config.dev.message_q_size).encode()
        mr.add_peer(msg_hash, msg_type, peer)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), config.dev.message_q_size)
        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request), config.dev.message_q_size)
        self.assertNotIn(b'0', mr._requested_hash._peer_to_msg_hash[peer])
        self.assertEqual(str(config.dev.message_q_size).encode(), mr._requested_hash._peer_to_msg_hash[peer][config.dev.message_q_size - 1])
        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request[msg_hash].peers_connection_list), 1)
        self.assertEqual(mr._requested_hash._msg_hash_msg_request[msg_hash].peers_connection_list[0], peer)

    def test_add_peer_same_msg_hash(self):
        '''
        Adding same message hash to a peer should bring message hash to the
        last position of the list.
        '''
        mr = MessageReceipt()
        target_size = 5

        msg_type = mr.allowed_types[0]
        initial_ip_addr = '127.0.0.1'
        peer = ipaddress.ip_address(initial_ip_addr)
        peer2 = peer + 1

        # Keep adding msg_hash upto maximum size limit
        for i in range(target_size):
            mr.add_peer(str(i).encode(), msg_type, peer)

        self.assertIn(peer, mr._requested_hash._peer_to_msg_hash)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), target_size)
        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request), target_size)
        self.assertEqual(b'0', mr._requested_hash._peer_to_msg_hash[peer][0])
        self.assertIn(b'0', mr._requested_hash._msg_hash_msg_request)
        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list), 1)
        self.assertEqual(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list[0], peer)

        mr.add_peer(b'0', msg_type, peer2)

        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list), 2)
        self.assertEqual(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list[0], peer)
        self.assertEqual(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list[1], peer2)

        # adding existing msg_hash with existing peer
        mr.add_peer(b'0', msg_type, peer)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), target_size)
        self.assertEqual(b'1', mr._requested_hash._peer_to_msg_hash[peer][0])
        self.assertEqual(b'0', mr._requested_hash._peer_to_msg_hash[peer][target_size - 1])
        self.assertIn(b'0', mr._requested_hash._msg_hash_msg_request)
        self.assertEqual(len(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list), 2)
        self.assertEqual(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list[0], peer)
        self.assertEqual(mr._requested_hash._msg_hash_msg_request[b'0'].peers_connection_list[1], peer2)

    def test_add_peer_same_msg_hash_2(self):
        '''
        Adding same message hash to a peer should bring message hash to the
        last position of the list.
        '''
        mr = MessageReceipt()
        target_size = 5

        msg_type = mr.allowed_types[0]
        initial_ip_addr = '127.0.0.1'
        peer = ipaddress.ip_address(initial_ip_addr)

        # Keep adding msg_hash upto maximum size limit
        for i in range(target_size):
            mr.add_peer(str(i).encode(), msg_type, peer)

        self.assertIn(peer, mr._requested_hash._peer_to_msg_hash)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), target_size)
        self.assertEqual(b'1', mr._requested_hash._peer_to_msg_hash[peer][1])

        # adding new msg_hash beyond size limit
        mr.add_peer(b'1', msg_type, peer)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), target_size)
        self.assertEqual(b'2', mr._requested_hash._peer_to_msg_hash[peer][1])
        self.assertEqual(b'1', mr._requested_hash._peer_to_msg_hash[peer][target_size - 1])

    def test_remove_peer(self):
        mr = MessageReceipt()

        msg_type = mr.allowed_types[0]
        initial_ip_addr = '127.0.0.1'
        peer = ipaddress.ip_address(initial_ip_addr)

        # Keep adding msg_hash upto maximum size limit
        for i in range(config.dev.message_q_size):
            mr.add_peer(str(i).encode(), msg_type, peer)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash), 1)
        self.assertIn(peer, mr._requested_hash._peer_to_msg_hash)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), config.dev.message_q_size)
        self.assertEqual(b'0', mr._requested_hash._peer_to_msg_hash[peer][0])

        # adding new msg_hash beyond size limit
        mr.add_peer(str(config.dev.message_q_size).encode(), msg_type, peer)

        self.assertEqual(len(mr._requested_hash._peer_to_msg_hash[peer]), config.dev.message_q_size)
        self.assertNotIn(b'0', mr._requested_hash._peer_to_msg_hash[peer])
        self.assertEqual(str(config.dev.message_q_size).encode(), mr._requested_hash._peer_to_msg_hash[peer][config.dev.message_q_size - 1])

    def test_contains(self):
        mr = MessageReceipt()

        msg_hash = str2bin("hash_valid")
        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]

        mr.register(msg_type, msg_hash, msg_obj)
        self.assertTrue(mr.contains(msg_hash, msg_type))

    def test_register_overflow(self):
        mr = MessageReceipt()

        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]

        config.dev.message_q_size = 4

        for i in range(config.dev.message_q_size * 2):
            msg_hash = str2bin(str(i))
            mr.register(msg_type, msg_hash, msg_obj)

        self.assertEqual(len(mr._hash_msg), config.dev.message_q_size)
