from unittest import TestCase
from mock import Mock

from qrl.core.MessageRequest import MessageRequest


class TestMessageRequest(TestCase):
    def setUp(self):
        self.mr = MessageRequest()

        self.test_data = {
            "camel": "animal",
            "bitcoin": "cryptocoin"
        }

    def test_validate(self):
        # MessageRequest.validate() simply make sure self.params and an arg are the same dict.
        # MessageRequest.params is None
        result = self.mr.validate(self.test_data)
        self.assertFalse(result)

        # MessageRequest.params is the same as the argument
        self.mr.params = self.test_data
        result = self.mr.validate(self.test_data)
        self.assertTrue(result)

        # MessageRequest.params is missing a key compared to the argument
        self.mr.params = {"bitcoin": "cryptocoin"}
        result = self.mr.validate(self.test_data)
        self.assertTrue(result)
        self.mr.params = self.test_data

        # the argument is missing a key that MessageRequest.params has
        result = self.mr.validate({})
        self.assertFalse(result)

        # the argument has different data from MessageRequest.params
        result = self.mr.validate({"camel": "cryptocoin", "bitcoin": "animal"})
        self.assertFalse(result)

    def test_add_peer(self):
        msg_type = Mock(name='mock Message Type')
        peer = Mock(name='mock P2PProtocol')

        self.mr.add_peer(msg_type, peer, params=self.test_data)

        self.assertEqual(self.mr.params, self.test_data)
        self.assertEqual(self.mr.msg_type, msg_type)
        self.assertEqual(self.mr.peers_connection_list, [peer])
