# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
import time
from unittest import TestCase

from mock import Mock, patch, mock
from pyqrllib.pyqrllib import hstr2bin
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.p2p.IPMetadata import IPMetadata
from qrl.core.p2p.p2pPeerManager import P2PPeerManager
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.generated import qrl_pb2, qrllegacy_pb2
from tests.misc.helper import replacement_getTime
from tests.misc.helper import set_qrl_dir

logger.initialize_default()


def make_channel(name=''):
    channel = Mock(autospec=P2PProtocol, name=name)
    channel.factory = Mock(autospec=P2PFactory)
    return channel


def make_node_chain_state():
    node_chain_state = qrl_pb2.NodeChainState(block_number=0,
                                              header_hash=b'',
                                              cumulative_difficulty=b'0' * 32,
                                              timestamp=int(time.time()))
    return node_chain_state


# Some functions have logger patched out, so that tests are not too noisy when unexpected things happen.
@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestP2PPeerManager(TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setUp(self):
        self.peer_manager = P2PPeerManager()

    def tearDown(self):
        del self.peer_manager

    def populate_peer_manager(self):
        channel_1 = make_channel('channel_1')
        channel_2 = make_channel('channel_2')
        channel_3 = make_channel('channel_3')

        self.peer_manager._channels = [channel_1, channel_2, channel_3]

        self.peer_manager._peer_node_status[channel_1] = make_node_chain_state()
        self.peer_manager._peer_node_status[channel_2] = make_node_chain_state()
        self.peer_manager._peer_node_status[channel_3] = make_node_chain_state()

        return channel_1, channel_2, channel_3

    def test_load_peer_addresses_peer_qrl(self):
        """
        Should load peers from peers.qrl AND from config.user.peer_list
        """
        with set_qrl_dir('peers') as tmp_dir:
            self.peer_manager.peers_path = os.path.join(tmp_dir, 'peers.json')

            self.peer_manager.load_peer_addresses()

            # This was in peers.qrl
            self.assertIn(IPMetadata.canonical_full_address('34.208.138.15'), self.peer_manager.known_peer_addresses)
            # config.user.peer_list is all in there too
            for p in config.user.peer_list:
                self.assertIn(IPMetadata.canonical_full_address(p), self.peer_manager.known_peer_addresses)

    def test_load_peer_addresses_no_file(self):
        """
        If no peers.qrl exists, use config.user.peer_list
        """
        with set_qrl_dir('no_data') as tmp_dir:
            self.peer_manager.peers_path = os.path.join(tmp_dir, config.dev.peers_filename)

            self.peer_manager.load_peer_addresses()

            # config.user.peer_list is all in there too
            self.assertEqual(len(config.user.peer_list), len(self.peer_manager.known_peer_addresses))
            for p in config.user.peer_list:
                self.assertIn(IPMetadata.canonical_full_address(p), self.peer_manager.known_peer_addresses)

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    def test_load_peer_addresses_corrupt_file(self, logger):
        """
        If peers.qrl is corrupt, load_peer_addresses should rewrite it with valid peers from config.user.peer_list
        """
        with set_qrl_dir('peers') as tmp_dir:
            self.peer_manager.peers_path = os.path.join(tmp_dir, 'peers_corrupt.json')

            self.peer_manager.load_peer_addresses()

            # config.user.peer_list is all in there too
            with open(os.path.join(tmp_dir, 'peers_corrupt.json')) as f:
                contents = f.read()
                for p in config.user.peer_list:
                    self.assertIn(p, contents)

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    def test_combine_peer_lists_works(self, logger):
        """
        combine_peer_lists takes: a set of IP:PORTs from a peer; the peer's ip; the peer's port
        It validates the set of IP:PORTs and adds valid ones to the node's peerlist.
        Global IP addresses only.
        Because we are connected to the peer from whom we downloaded this list, the peer's ip and port are validated
        differently and added to the peerlist as well.
        If the same IP appears with different ports, they should appear as different records in the peerlist (max 2)
        """
        # The second IP in the set has an invalid port, but the peer to which we are connected should be in the set.
        result = self.peer_manager.combine_peer_lists({'1.1.1.1:9000', '1.2.3.4:65536'},
                                                      ['187.0.0.1:1000'], check_global=True)
        self.assertEqual(result, {'1.1.1.1:9000', '187.0.0.1:1000'})

        # What happens if the peer we are connected to now has a different port? it should replace the entry in the set.
        result = self.peer_manager.combine_peer_lists({'1.1.1.1:9000', '127.0.0.1:1000'},
                                                      ['187.0.0.1:2000'], check_global=True)
        self.assertEqual(result, {'1.1.1.1:9000', '187.0.0.1:2000'})

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    def test_combine_peer_lists_bad_ip_list(self, logger):
        """
        combine_peer_lists should revalidate all existing ip:port pairs when adding a new one to the list.
        but why isn't validation happening in another layer so that the set is always clean?
        """
        bad_ip_list_result = self.peer_manager.combine_peer_lists({'256.256.256.256:9000', '187.0.0.3:90000'},
                                                                  ['187.0.0.1:9000'], check_global=True)
        self.assertEqual(bad_ip_list_result, {'187.0.0.1:9000'})

        # A local IP in the incoming set should be ignored.
        result = self.peer_manager.combine_peer_lists({'1.1.1.1:8000', '127.0.0.1:1111'},
                                                      ['127.0.0.1:3000'], check_global=True)
        self.assertEqual(result, {'1.1.1.1:8000'})

        # A bad IP in the set should not pass.
        result = self.peer_manager.combine_peer_lists({'255.255.255.255:8000'},
                                                      ['127.0.0.1:3000'], check_global=True)
        self.assertEqual(result, set())

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    def test_update_peer_addresses_also_connects_to_new_peers(self, logger):
        """
        extend_known_peers() not only writes out, it automatically connects to any new peers.
        """
        self.peer_manager._p2pfactory = Mock()
        self.peer_manager._known_peers = {'1.1.1.1:9000'}
        with set_qrl_dir('no_data') as tempdir:
            self.peer_manager.peers_path = os.path.join(tempdir, config.dev.peers_filename)
            self.peer_manager.extend_known_peers({'2.2.2.2:9000'})

        self.peer_manager._p2pfactory.connect_peer.assert_called_once_with('2.2.2.2:9000')

    def test_remove_channel(self):
        """
        For each channel in _channels, there should be a corresponding entry in _peer_node_status.
        remove_channel() makes sure there is a 1:1 correspondence.

        It also shouldn't make trouble if the _peer_node_status is missing.
        """
        channel_2, channel_3 = self.populate_peer_manager()[1:3]

        self.peer_manager.remove_channel(channel_3)
        self.assertEqual(len(self.peer_manager._channels), 2)
        self.assertEqual(len(self.peer_manager._peer_node_status), 2)

        # It also shouldn't make trouble if the _peer_node_status is missing.
        del self.peer_manager._peer_node_status[channel_2]
        self.peer_manager.remove_channel(channel_2)
        self.assertEqual(len(self.peer_manager._channels), 1)
        self.assertEqual(len(self.peer_manager._peer_node_status), 1)

    def test_new_channel(self):
        """
        new_channel() makes sure that for each channel P2PPeerManager has in _channels, there is a corresponding
        record in _peer_node_status.
        It also tells the channel to call P2PPeerManager's handle_* functions whenever certain messages come in.
        """
        channel = make_channel()
        self.peer_manager.new_channel(channel)
        self.assertEqual(len(self.peer_manager._channels), len(self.peer_manager._peer_node_status), 1)

        self.assertEqual(channel.register.call_count, 5)

    def test_handle_version(self):
        """
        When a version message arrives from a peer, and all else is normal:
        A version request message was not sent to the peer.
        The peer is not banned.
        P2PProtocol.loseConnection() is not called.
        """
        channel = make_channel()

        message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                              veData=qrllegacy_pb2.VEData(version=config.dev.version,
                                                                          genesis_prev_hash=config.user.genesis_prev_headerhash,
                                                                          rate_limit=config.user.peer_rate_limit))
        self.peer_manager.handle_version(channel, message)
        channel.peer_manager.ban_channel.assert_not_called()
        channel.loseConnection.assert_not_called()

    def test_handle_version_empty_version_message(self):
        """
        If the incoming version message has an empty version field, then send another version request.
        That message should have the node's version in it.
        """
        channel = make_channel()

        message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                              veData=qrllegacy_pb2.VEData(version='',
                                                                          genesis_prev_hash=config.user.genesis_prev_headerhash,
                                                                          rate_limit=config.user.peer_rate_limit))
        self.peer_manager.handle_version(channel, message)
        self.assertEqual(channel.send.call_args[0][0].veData.version, config.dev.version)

    def test_handle_version_wrong_genesis_prev_headerhash(self):
        """
        If the genesis_prev_headerhash is different, the nodes should disconnect from each other.
        """
        channel = make_channel()

        message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                              veData=qrllegacy_pb2.VEData(version=config.dev.version,
                                                                          genesis_prev_hash=b'TEST123',
                                                                          rate_limit=config.user.peer_rate_limit))
        self.peer_manager.handle_version(channel, message)
        channel.loseConnection.assert_any_call()

    def test_get_better_difficulty(self):
        """
        Returns the P2PProtocol that has a higher cumulative difficulty than our node.
        Should not take any other variable into account,including block_number or timestamp.
        Also updates the 'best seen cumulative difficulty' variable.
        """
        test_cumulative_difficulty = StringToUInt256('5000')

        channel_1, channel_2, channel_3 = self.populate_peer_manager()

        self.peer_manager._peer_node_status[channel_1].cumulative_difficulty = bytes(StringToUInt256('5001'))
        self.peer_manager._peer_node_status[channel_2].cumulative_difficulty = bytes(StringToUInt256('0'))
        self.peer_manager._peer_node_status[channel_3].cumulative_difficulty = bytes(StringToUInt256('3'))

        self.assertEqual(self.peer_manager.get_better_difficulty(test_cumulative_difficulty), channel_1)

        # But channel_1 has a very old timestamp! doesn't matter.
        self.peer_manager._peer_node_status[channel_1].timestamp = 1400000000
        self.assertEqual(self.peer_manager.get_better_difficulty(test_cumulative_difficulty), channel_1)

        # But other nodes have higher blockheight! Doesn't matter
        self.peer_manager._peer_node_status[channel_1].block_number = 1
        self.peer_manager._peer_node_status[channel_2].block_number = 4
        self.peer_manager._peer_node_status[channel_3].block_number = 5

        self.assertEqual(self.peer_manager.get_better_difficulty(test_cumulative_difficulty), channel_1)

    def test_get_better_difficulty_self(self):
        """
        If we have the highest cum-difficulty, this function should return None.
        """
        test_cumulative_difficulty = StringToUInt256('5000')
        channel_1, channel_2, channel_3 = self.populate_peer_manager()

        self.peer_manager._peer_node_status[channel_1].cumulative_difficulty = bytes(StringToUInt256('49'))
        self.peer_manager._peer_node_status[channel_2].cumulative_difficulty = bytes(StringToUInt256('4800'))
        self.peer_manager._peer_node_status[channel_3].cumulative_difficulty = bytes(StringToUInt256('3'))

        self.assertIsNone(self.peer_manager.get_better_difficulty(test_cumulative_difficulty))

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    def test_handle_peer_list_works(self, logger):
        """
        Heavy error testing should be done in combine_peer_lists() and extend_known_peers(), which this fx uses.
        """
        peer_list_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                                        plData=qrllegacy_pb2.PLData(
                                                            peer_ips={'127.0.0.3:5000', '127.0.0.4:5001'},
                                                            public_port=9000))
        channel = make_channel()
        channel.host = IPMetadata('187.0.0.1', 9000)
        channel.peer = IPMetadata('187.0.0.2', 9000)

        # handle_peer_list() will call extend_known_peers(), so we gotta mock it out. It's tested elsewhere anyway.
        self.peer_manager.extend_known_peers = Mock(autospec=P2PPeerManager.extend_known_peers)
        self.peer_manager.handle_peer_list(channel, peer_list_message)
        self.peer_manager.extend_known_peers.assert_called_once_with({channel.peer.full_address})

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    def test_handle_peer_list_empty_peer_list_message(self, logger):
        """
        An empty plData should result in no further processing being done.
        """
        peer_list_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                                        plData=qrllegacy_pb2.PLData(peer_ips={}, public_port=9000))
        channel = make_channel()
        channel.host_ip = '127.0.0.1'
        channel.peer_ip = '127.0.0.2'

        self.peer_manager.extend_known_peers = Mock(autospec=P2PPeerManager.extend_known_peers)
        self.peer_manager.combine_peer_lists = Mock(autospec=P2PPeerManager.combine_peer_lists)

        self.peer_manager.handle_peer_list(channel, peer_list_message)

        self.peer_manager.combine_peer_lists.assert_not_called()
        self.peer_manager.extend_known_peers.assert_not_called()

    @patch('qrl.core.p2p.p2pPeerManager.logger', autospec=True)
    @patch('qrl.core.p2p.p2pPeerManager.config', autospec=True)
    def test_handle_peer_list_peer_discovery_disabled(self, config, logger):
        """
        If enable_peer_discovery is False, no further processing should be done.
        """
        config.user.enable_peer_discovery = False
        peer_list_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                                        plData=qrllegacy_pb2.PLData(
                                                            peer_ips={'127.0.0.3:5000', '127.0.0.4:5001'},
                                                            public_port=9000))
        channel = make_channel()
        channel.host_ip = '127.0.0.1'
        channel.peer_ip = '127.0.0.2'

        self.peer_manager.extend_known_peers = Mock(autospec=P2PPeerManager.extend_known_peers)
        self.peer_manager.combine_peer_lists = Mock(autospec=P2PPeerManager.combine_peer_lists)

        self.peer_manager.handle_peer_list(channel, peer_list_message)

        self.peer_manager.combine_peer_lists.assert_not_called()
        self.peer_manager.extend_known_peers.assert_not_called()

    def test_handle_sync(self):
        """
        If a message comes in saying 'Synced': the peer is synced.
        """
        sync_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                                   syncData=qrllegacy_pb2.SYNCData(state='Synced'))
        channel = make_channel()

        self.peer_manager.handle_sync(channel, sync_message)

    def test_handle_sync_unsynced(self):
        """
        If the message says anything else: the peer is unsynced.
        """
        sync_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                                   syncData=qrllegacy_pb2.SYNCData(state='Unsynced'))
        channel = make_channel()

        self.peer_manager.handle_sync(channel, sync_message)

    def test_handle_sync_blank(self):
        """
        If the message says '': the peer doesn't know, and isn't synced. We tell it that we are synced.
        """
        sync_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                                   syncData=qrllegacy_pb2.SYNCData(state=''))
        channel = make_channel()

        # But if we ourselves aren't synced, then we cannot say if anybody else is synced.
        channel.factory.synced = False
        self.peer_manager.handle_sync(channel, sync_message)
        channel.send_sync.assert_not_called()

        # If we are synced, then we can tell other nodes we are synced.
        channel.factory.synced = True
        self.peer_manager.handle_sync(channel, sync_message)
        channel.send_sync.assert_called_once_with(synced=True)

    def test_monitor_chain_state_works(self):
        """
        This function simply goes through each channel in P2PPeerManager and make sure the info it has on that
        is fresh. After a certain time period, the information is considered stale and the channel will be disconnected.
        If it doesn't have info on a particular P2PProtocol, then it will disconnect the channel
        (presumably the information should already have been exchanged when the channel was first connected)
        """
        channel_1, channel_2, channel_3 = self.populate_peer_manager()

        self.peer_manager.monitor_chain_state()

        channel_1.loseConnection.assert_not_called()
        channel_2.loseConnection.assert_not_called()
        channel_3.loseConnection.assert_not_called()

    def test_monitor_chain_state_stale_info(self):
        """
        After a certain time period, the information is considered stale and the channel will be disconnected.
        """
        channel_1 = self.populate_peer_manager()[0]
        self.peer_manager._peer_node_status[channel_1].timestamp = int(
            time.time()) - config.user.chain_state_timeout - 1

        self.peer_manager.monitor_chain_state()

        channel_1.loseConnection.assert_called_once_with()

    def test_monitor_chain_state_extra_channel(self):
        """
        If monitor_chain-state() doesn't have info on a particular P2PProtocol, then it will disconnect the channel
        new_channel() should have put the info there into _peer_node_status after all.
        """
        channel_3 = self.populate_peer_manager()[2]

        del self.peer_manager._peer_node_status[channel_3]

        self.peer_manager.monitor_chain_state()

        channel_3.loseConnection.assert_called_once_with()

    def test_handle_chain_state_works(self):
        """
        When a peer reports its chain state, we update the timestamp to reflect the time we received the message.
        Then we update our _peer_node_status.
        """
        chain_state_data = make_node_chain_state()

        chain_state_message = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.CHAINSTATE,
                                                          chainStateData=chain_state_data)
        channel = make_channel()

        # The P2PPeerManager should update its hash table with the info from chain_state_data.
        # Unfortunately it also updates the timestamp so we cannot simply compare the objects,
        # we have to compare the fields in the object excluding the timestamp.
        self.peer_manager.handle_chain_state(channel, chain_state_message)

        self.assertEqual(self.peer_manager._peer_node_status[channel].block_number, chain_state_data.block_number)
        self.assertEqual(self.peer_manager._peer_node_status[channel].header_hash, chain_state_data.header_hash)
        self.assertEqual(self.peer_manager._peer_node_status[channel].cumulative_difficulty,
                         chain_state_data.cumulative_difficulty)

    def test_handle_p2p_acknowledgement(self):
        """
        Once an acknowledgement is received from a peer, we can update rate counters and send the next message.
        """
        ack = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.P2P_ACK,
                                          p2pAckData=qrl_pb2.P2PAcknowledgement(bytes_processed=15))
        channel = make_channel()
        channel.bytes_sent = 20
        self.peer_manager.handle_p2p_acknowledgement(channel, ack)

        channel.send_next.assert_called_once_with()

    def test_handle_p2p_acknowledgement_negative_bytes_processed(self):
        """
        If we sent 10 bytes to the peer, but the peer says it processed 20 bytes, disconnect the peer.
        """
        ack = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.P2P_ACK,
                                          p2pAckData=qrl_pb2.P2PAcknowledgement(bytes_processed=20))
        channel = make_channel()
        channel.bytes_sent = 10
        self.peer_manager.handle_p2p_acknowledgement(channel, ack)

        channel.loseConnection.assert_called_once_with()

    @patch('qrl.core.p2p.p2pprotocol.P2PProtocol.peer')
    @patch('qrl.core.p2p.p2pprotocol.P2PProtocol.send')
    def test_trusted_message_count(self, send, get_peer):
        channel = P2PProtocol()
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = channel.connected_at + 100
            get_peer.return_value = IPMetadata('192.168.0.1', 1000)

            self.assertFalse(self.peer_manager.trusted_peer(channel))

            for _ in range(config.dev.trust_min_msgcount - 1):
                buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'))
                channel.dataReceived(buffer)
                self.assertFalse(self.peer_manager.trusted_peer(channel))

            buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'))
            channel.dataReceived(buffer)
            self.assertTrue(self.peer_manager.trusted_peer(channel))

    @patch('qrl.core.p2p.p2pprotocol.P2PProtocol.peer')
    @patch('qrl.core.p2p.p2pprotocol.P2PProtocol.send')
    def test_trusted_time(self, send, get_peer):
        channel = P2PProtocol()
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = channel.connected_at + 1
            get_peer.return_value = IPMetadata('192.168.0.1', 1000)

            for _ in range(config.dev.trust_min_msgcount):
                buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'))
                channel.dataReceived(buffer)

            time_mock.return_value = channel.connected_at + config.dev.trust_min_conntime + 1
            self.assertTrue(self.peer_manager.trusted_peer(channel))
