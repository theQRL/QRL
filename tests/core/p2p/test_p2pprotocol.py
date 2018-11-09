# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple
from unittest import TestCase

from mock import Mock, patch, MagicMock
from pyqrllib.pyqrllib import hstr2bin, bin2hstr

from qrl.core.misc import logger
from qrl.core.p2p import p2pPeerManager
from qrl.core.p2p.p2pfactory import P2PFactory, p2p_msg_priority
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrllegacy_pb2
from tests.misc.helper import replacement_getTime

logger.initialize_default()

Host = namedtuple('Host', ['host', 'port'])


# FIXME: These tests will soon be removed
class TestP2PProtocol(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PProtocol, self).__init__(*args, **kwargs)

    def setUp(self):
        with patch('qrl.core.misc.ntp.getTime', new=replacement_getTime):
            self.channel = P2PProtocol()

        self.channel._observable = Mock()

        self.channel.factory = Mock(autospec=P2PFactory)
        self.channel.factory.p2p_msg_priority = p2p_msg_priority
        self.channel.factory._qrl_node = Mock(autospec=QRLNode)
        self.channel.factory._qrl_node.peer_manager = Mock(autospec=p2pPeerManager)
        self.channel.factory._qrl_node.peer_manager.is_banned = MagicMock(return_value=False)
        self.channel.factory._qrl_node.peer_manager.trusted_addresses = MagicMock(return_value=[])

        sample_peer_1 = Host('127.0.0.2', '9000')
        sample_host = Host('127.0.0.1', '9000')
        attrs = {'getPeer.return_value': sample_peer_1, 'getHost.return_value': sample_host}
        self.channel.transport = Mock(**attrs)

    def tearDown(self):
        del self.channel

    def test_addr_remote_works(self):
        """
        This is more to ensure that the transport is mocked correctly.
        """
        self.assertEqual('127.0.0.2:9000', self.channel.peer.full_address)

    def test_addr_local_works(self):
        """
        This is more to ensure that the transport is mocked correctly.
        """
        self.assertEqual('127.0.0.1:9000', self.channel.host.full_address)

    @patch('qrl.core.misc.ntp.getTime')
    def test_connectionMade_behavior(self, getTime):
        """
        When connectionMade, the Managers (Observers) must be informed once, and peer list, version request messages
        must be in the outgoing message queue.
        ntp.getTime() is patched everywhere, not just in p2pprotocol, because OutgoingMessage uses it too.
        """
        self.channel.factory.get_connected_peer_addrs.return_value = {'127.0.0.2:9000'}

        getTime.return_value = 1525078652.9991353
        self.channel.connectionMade()

        # Managers were notified
        self.channel.p2pchain_manager.new_channel.assert_called_once_with(self.channel)
        self.channel.peer_manager.new_channel.assert_called_once_with(self.channel)
        self.channel.tx_manager.new_channel.assert_called_once_with(self.channel)

        # send_peer_list and send_version_request messages should be in the outgoing queue.
        self.assertEqual(self.channel.outgoing_queue.unfinished_tasks, 2)

    def test_connectionLost_behavior(self):
        """
        When connectionLost, peer_manager (an Observer) is notified. (why not other Observers?)
        """
        self.channel.connectionLost()
        self.channel.peer_manager.remove_channel.assert_called_once_with(self.channel)

    @patch('qrl.core.misc.ntp.getTime')
    def test_dataReceived_normal_message(self, getTime):
        """
        Ensure that dataReceived works as expected with a normal message.
        """
        getTime.return_value = 1525078652.9991353
        data = b'\x00\x00\x00\x80\x08\x01"|\n\x0e66.175.217.203\n\x0e138.195.214.85\n\r35.177.72.178\n\x0e173.249.22.240\n\x0c2.238.131.20\n\r77.64.144.198\n\r34.208.138.15\n\x0f144.202.107.148\x00\x00\x00\x00'  # noqa
        self.channel.dataReceived(data)

        # Twisted transport should have received acknowledgement message to send out
        acknowledgement_bytes = b'\x00\x00\x00\x08\x08\x13\xaa\x01\x03\x08\x84\x01'
        self.channel.transport.write.assert_called_once_with(acknowledgement_bytes)

    @patch('qrl.core.misc.ntp.getTime')
    @patch('qrl.core.p2p.p2pprotocol.logger', autospec=True)
    @patch('qrl.core.p2p.p2pprotocol.config.dev', autospec=True)
    def test_dataReceived_too_big(self, config_dev, logger, getTime):
        """
        Normally the buffer size upper limit is 10MB. But we're going to patch it smaller here.
        """
        config_dev.max_bytes_out = 10
        config_dev.trust_min_msgcount = 10
        getTime.return_value = 1525078652.9991353
        acknowledgement_bytes = b'\x00\x00\x00\x08\x08\x13\xaa\x01\x03\x08\x88\x01'
        self.channel._buffer = 10 * acknowledgement_bytes
        self.channel.dataReceived(acknowledgement_bytes)
        self.channel.transport.loseConnection.assert_called()

    @patch('qrl.core.misc.ntp.getTime')
    def test_dataReceived_spam_ban_peer(self, getTime):
        getTime.return_value = 1525078652.9991353
        self.channel.rate_limit = 2
        acknowledgement_bytes = b'\x00\x00\x00\x08\x08\x13\xaa\x01\x03\x08\x88\x01'
        self.channel._buffer = 10 * acknowledgement_bytes
        self.channel.dataReceived(acknowledgement_bytes)
        self.channel.peer_manager.ban_channel.assert_called_with(self.channel)

    @patch('qrl.core.misc.ntp.getTime')
    def test_send_version_request(self, getTime):
        getTime.return_value = 1525078652.9991353
        version_request = b'\x00\x00\x00\x02\x1a\x00'
        self.channel.send_version_request()
        self.channel.transport.write.assert_called_with(version_request)

    @patch('qrl.core.misc.ntp.getTime')
    def test_send_sync(self, getTime):
        getTime.return_value = 1525078652.9991353
        self.channel.send_sync(synced=True)
        synced = b'\x00\x00\x00\r\x08\x10\x92\x01\x08\n\x06Synced'
        self.channel.transport.write.assert_called_with(synced)

        self.channel.send_sync(synced=False)
        unsynced = b'\x00\x00\x00\x05\x08\x10\x92\x01\x00'
        self.channel.transport.write.assert_called_with(unsynced)

    @patch('qrl.core.misc.ntp.getTime')
    def test_send_fetch_block(self, getTime):
        getTime.return_value = 1525078652.9991353
        block_request = b'\x00\x00\x00\x06\x08\x06B\x02\x08\x01'
        self.channel.send_fetch_block(1)
        self.channel.transport.write.assert_called_with(block_request)

    @patch('qrl.core.misc.ntp.getTime')
    def test_get_headerhash_list(self, getTime):
        getTime.return_value = 1525078652.9991353
        get_headerhash_request = b'\x00\x00\x00\x05\x08\x12\xa2\x01\x00'
        self.channel.send_get_headerhash_list(1)
        self.channel.transport.write.assert_called_with(get_headerhash_request)

    def test_parse_buffer_works(self):
        self.channel._buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368' +
                                              '000000191a170a0776657273696f6e120c67656e657369735f68617368'))
        messages = self.channel._parse_buffer([0])
        self.assertEqual(2, len(list(messages)))

    @patch('qrl.core.p2p.p2pprotocol.logger', autospec=True)
    def test_parse_buffer_invalid_data(self, logger):
        self.channel._buffer = bytes(hstr2bin('0000000000000000000000000000000000000000000000000000000000' +
                                              '1111111111111111111111111111111111111111111111111111111111'))

        messages = self.channel._parse_buffer([0])
        messages_list = list(messages)
        self.assertEqual(0, len(messages_list))
        logger.warning.assert_called_with("Problem parsing message. Banning+Dropping connection")

    def test_wrap_message_works(self):
        veData = qrllegacy_pb2.VEData(version="version", genesis_prev_hash=b'genesis_hash')
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE, veData=veData)
        self.assertEqual('000000191a170a0776657273696f6e120c67656e657369735f68617368',
                         bin2hstr(P2PProtocol._wrap_message(msg)))
