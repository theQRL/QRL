# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger, config
from qrl.core.messagereceipt import MessageReceipt
from qrl.crypto.misc import sha256

logger.initialize_default(force_console_output=True)


class TestMessageReceipt(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMessageReceipt, self).__init__(*args, **kwargs)

    def test_create(self):
        mr = MessageReceipt()
        self.assertIsNotNone(mr)
        self.assertEqual(mr.allowed_types, ['TX', 'ST', 'BK', 'R1'])

    def test_register(self):
        mr = MessageReceipt()

        msg_hash = "asdf"
        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]

        mr.register(msg_hash, msg_obj, msg_type)

    def test_add_contains_remove(self):
        mr = MessageReceipt()
        # FIXME: Hashes being are treated as strings

        msg_hash = "hash_valid"
        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]
        peer = '127.0.0.1'

        mr.register(msg_hash, msg_obj, msg_type)
        mr.add_peer(msg_hash, msg_type, peer)

        # FIXME: Unexpected API. Contains does not operate on the same registered key
        msg_hash_key = sha256(str(msg_hash))

        self.assertTrue(mr.contains(msg_hash_key, msg_type))
        self.assertFalse(mr.contains('hash_invalid', msg_type))

    def test_contains(self):
        mr = MessageReceipt()

        msg_hash = "hash_valid"
        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]

        # FIXME: Unexpected API. Contains does not operate on the same registered key
        msg_hash_key = sha256(str(msg_hash))

        mr.register(msg_hash, msg_obj, msg_type)
        self.assertTrue(mr.contains(msg_hash_key, msg_type))

    def test_register_overflow(self):
        mr = MessageReceipt()

        msg_obj = [1, 2, 3, 4]
        msg_type = mr.allowed_types[0]

        config.dev.message_q_size = 4

        for i in range(config.dev.message_q_size * 2):
            msg_hash = i
            mr.register(msg_hash, msg_obj, msg_type)

        self.assertEqual(len(mr.hash_type), config.dev.message_q_size)
