# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from unittest import TestCase

from mock import Mock, patch
from pyqrllib.pyqrllib import hstr2bin
from pyqryptonight.pyqryptonight import StringToUInt256
from twisted.internet import reactor

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.State import State
from qrl.core.ChainManager import ChainManager
from qrl.core.Message import Message
from qrl.core.MessageRequest import MessageRequest
from qrl.core.misc import logger
from qrl.core.node import POW
from qrl.core.p2p.IPMetadata import IPMetadata
from qrl.core.p2p.p2pPeerManager import P2PPeerManager
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.core.qrlnode import QRLNode
from qrl.core.txs.MessageTransaction import MessageTransaction
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.generated import qrl_pb2, qrllegacy_pb2
from tests.misc.helper import replacement_getTime

logger.initialize_default()


def bhstr2bin(a_string: str) -> bytes:
    return bytes(hstr2bin(a_string))


def make_message(**kwargs):
    return qrllegacy_pb2.LegacyMessage(**kwargs)


def make_address(ip, port=config.user.p2p_public_port):
    return '{}:{}'.format(ip, port)


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
@patch('qrl.core.p2p.p2pfactory.logger', autospec=logger, name="Mock Logger")
@patch('qrl.core.p2p.p2pfactory.reactor', autospec=reactor, name="My Mock Reactor")
class TestP2PFactory(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PFactory, self).__init__(*args, **kwargs)

    def setUp(self):
        self.m_qrlnode = Mock(autospec=QRLNode, name='Fake QRLNode')
        self.m_qrlnode.peer_manager = Mock(autospec=P2PPeerManager, name='Fake PeerManager')
        self.m_qrlnode.peer_manager.is_banned.return_value = False

        self.channel_1 = Mock(autospec=P2PProtocol,
                              name='mock Channel 1',
                              peer=IPMetadata('1.1.1.1', config.user.p2p_public_port))
        self.channel_2 = Mock(autospec=P2PProtocol,
                              name='mock Channel 2',
                              peer=IPMetadata('2.2.2.2', config.user.p2p_public_port))
        self.channel_3 = Mock(autospec=P2PProtocol,
                              name='mock Channel 3',
                              peer=IPMetadata('3.3.3.3', config.user.p2p_public_port))

        self.factory = P2PFactory(chain_manager=ChainManager(state=Mock(autospec=State)), sync_state=None, qrl_node=self.m_qrlnode)
        self.factory.pow = Mock(autospec=POW)

        self.factory.add_connection(self.channel_1)
        self.factory.add_connection(self.channel_2)
        self.factory.add_connection(self.channel_3)

    def tearDown(self):
        self.factory.remove_connection(self.channel_1)
        self.factory.remove_connection(self.channel_2)
        self.factory.remove_connection(self.channel_3)

    def test_create_factory(self, m_reactor, m_logger):
        factory = P2PFactory(chain_manager=ChainManager(None), sync_state=None, qrl_node=None)
        self.assertEqual(P2PProtocol, factory.protocol,
                         "Factory has not been assigned the expected protocol")

    @patch('qrl.core.p2p.p2pfactory.config', autospec=True)
    def test_add_connection_connection_limit(self, m_config, m_reactor, m_logger):
        """
        When we've reached the connection_limit, add_connection() should refuse to do anything.
        In fact, it should disconnect the P2PProtocol.
        """
        channel_4 = Mock(autospec=P2PProtocol,
                         name='mock Channel 4',
                         peer=IPMetadata('4.4.4.4', 9000))

        m_config.user.max_peers_limit = 3
        m_config.user.max_redundant_connections = 5

        self.assertFalse(self.factory.add_connection(channel_4))

        self.assertEqual(self.factory.num_connections, 3)

    @patch('qrl.core.p2p.p2pfactory.config', autospec=True)
    def test_add_connection_redundant_connection_limit(self, m_config, m_reactor, m_logger):
        """
        When we've reached the max_redundant_connections, then the peer should be disconnected.
        """
        channel_4 = Mock(autospec=P2PProtocol,
                         name='mock Channel 1',
                         peer=IPMetadata('1.1.1.1', 9000))

        m_config.user.max_peers_limit = 5
        m_config.user.max_redundant_connections = 2

        self.assertTrue(self.factory.add_connection(channel_4))
        self.assertFalse(self.factory.add_connection(channel_4))

        self.assertEqual(self.factory.num_connections, 4)

    def test_add_connection_wont_connect_to_itself(self, m_reactor, m_logger):
        """
        P2PFactory should refuse to connect to a P2PProtocol which seems to have our own IP address
        P2PProtocol.host_ip should always be our IP address.
        If add_connection() detects this, then it will rebuild the peer_list, excluding this IP address.
        """
        channel_4 = Mock(autospec=P2PProtocol, name='mock Channel 4',
                         host=IPMetadata('4.4.4.4', config.user.p2p_public_port),
                         peer=IPMetadata('4.4.4.4', config.user.p2p_public_port))
        self.factory._qrl_node.peer_manager.known_peer_addresses = [make_address('1.1.1.1'),
                                                                    make_address('2.2.2.2'),
                                                                    make_address('3.3.3.3'),
                                                                    make_address('4.4.4.4')]
        self.assertFalse(self.factory.add_connection(channel_4))

        self.assertEqual(self.factory.num_connections, 3)
        self.factory._qrl_node.peer_manager.extend_known_peers.assert_called_once_with(
            [make_address('1.1.1.1'), make_address('2.2.2.2'), make_address('3.3.3.3')])

    def test_is_block_present(self, m_reactor, m_logger):
        """
        is_block_present() returns True if block's headerhash is in our blockchain, or if it is known and will be
        processed in the future (POW.future_blocks, OrderedDict())
        """
        self.factory.pow.future_blocks = OrderedDict()
        self.factory._chain_manager._state.get_block.return_value = False
        result = self.factory.is_block_present(b'1234')
        self.assertFalse(result)

        self.factory.pow.future_blocks = OrderedDict({b'1234': 'Some data'})
        result = self.factory.is_block_present(b'1234')
        self.assertTrue(result)

        self.factory.pow.future_blocks = OrderedDict()
        self.factory._chain_manager._state.get_block.return_value = True
        result = self.factory.is_block_present(b'1234')
        self.assertTrue(result)

    def test_connect_peer_already_connected(self, m_reactor, m_logger):
        """
        connect_peer() should not connect to already connected peers.
        We are connected to 1.1.1.1, 2.2.2.2, 3.3.3.3
        :param m_reactor:
        :param m_logger:
        :return:
        """
        self.factory.connect_peer(make_address('1.1.1.1'))
        m_reactor.connectTCP.assert_not_called()

        m_reactor.connectTCP.reset_mock()
        self.factory.connect_peer('1.1.1.1')
        m_reactor.connectTCP.assert_not_called()

    def test_connect_peer(self, m_reactor, m_logger):
        """
        connecting to previously unconnected peers should work.
        """
        self.factory.connect_peer('127.0.0.1:9000')
        m_reactor.connectTCP.assert_called_once()

        m_reactor.connectTCP.reset_mock()
        self.factory.connect_peer('5.5.5.5:9000')
        m_reactor.connectTCP.assert_called_once()

        m_reactor.connectTCP.reset_mock()
        self.factory.connect_peer('5.5.5.5')
        m_reactor.connectTCP.assert_called_once()

    def test_connect_peer_bad_ipport(self, m_reactor, m_logger):
        self.factory.connect_peer('1.1.1.1:65536')
        m_reactor.connectTCP.assert_not_called()

        self.factory.connect_peer('1.1.1.1:')
        m_reactor.connectTCP.assert_not_called()

    def test_monitor_connections(self, m_reactor, m_logger):
        """
        Tries to connect to trusted peers in config.user.peer_list, if they're not already connected.
        Since this function runs periodically, it ensures that the node will always periodically try to connect
        to these preferred peer IPs.

        If it is not connected to any peer, it won't do anything, because its job is to MONITOR, not to connect to
        new peers.
        """
        self.factory.connect_peer = Mock(autospec=P2PFactory.connect_peer)
        with patch('qrl.core.p2p.p2pfactory.config', autospec=True) as m_config:
            m_config.user.peer_list = ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4']
            self.factory.monitor_connections()
            self.factory.connect_peer.assert_called_once_with(make_address('4.4.4.4'))

    def test_monitor_connections_no_peers_connected(self, m_reactor, m_logger):
        self.factory.remove_connection(self.channel_1)
        self.factory.remove_connection(self.channel_2)
        self.factory.remove_connection(self.channel_3)

        self.factory.connect_peer = Mock(autospec=P2PFactory.connect_peer)
        self.factory.monitor_connections()
        self.factory.connect_peer.assert_not_called()

    def test_request_full_message(self, m_reactor, m_logger):
        """
        MessageReceipt is only for Blocks and Transactions, both of which have hashes.
        When you receive the MessageReceipt for them, if you find that you don't have that message corresponding to the
        hash, this is when you call request_full_message()

        If the local node already has the Message, its hash will be in self.master_mr._hash_msg (perhaps it got it
        from another peer). So in that case we check if we requested this hash from any other peer.
        if yes then delete that request and then we go through peer list, who broadcasted this same MR.

        and we request from any one of those peer, and we add that peer into our list, that we already have requested
        from this peer.

        We also make the callLater to the request_full_message, so that in a given interval of time,
        if peer doesn't respond, then we can request to next peer otherwise we can delete all the request, if we
        received it from the peer
        """
        # The local node does not already have this message.
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL, hash=b'1234')

        # You can get this Message from channel_1. No, we have not requested this Message from channel_1 yet.
        message_request = MessageRequest()
        message_request.peers_connection_list.append(self.channel_1)
        message_request.already_requested_peers = []
        self.factory.master_mr.requested_hash[b'1234'] = message_request

        self.factory.request_full_message(mrData)

        self.channel_1.send.assert_called_once()

        # We use reactor.callLater() to schedule a call to request_full_message() again in the future.
        # So if this peer doesn't respond, when this function is next called again, it will ignore this peer
        # because of already_requested_peers and use the next one in peers_list.
        m_reactor.callLater.assert_called_once()

    def test_request_full_message_already_requested_this_message_from_another_peer(self, m_reactor, m_logger):
        """
        If we have already requested this Message (from another peer), this function should still go ahead
        and request it from the peer we are currently dealing with.
        """
        # The local node does not already have this message.
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL, hash=b'1234')

        # You can get this Message from channel_1. Also, we already requested this Message from channel_2.
        message_request = MessageRequest()
        message_request.peers_connection_list.append(self.channel_1)
        message_request.already_requested_peers = [self.channel_2]
        self.factory.master_mr.requested_hash[b'1234'] = message_request

        self.factory.request_full_message(mrData)

        # But, the code should ignore channel_2 and ask channel_1 anyway.
        self.channel_1.send.assert_called_once()

        # We use reactor.callLater() to schedule a call to request_full_message() again in the future.
        # So if this peer doesn't respond, when this function is next called again, it will ignore this peer
        # because of already_requested_peers and use the next one in peers_list.
        m_reactor.callLater.assert_called_once()

    def test_request_full_message_already_requested_this_message_from_same_peer(self, m_reactor, m_logger):
        # The local node does not already have this message.
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL, hash=b'1234')

        # You can get this Message from channel_1 and channel_2. Also, we already requested this Message from channel_1.
        message_request = MessageRequest()
        message_request.peers_connection_list = [self.channel_1, self.channel_2]
        message_request.already_requested_peers = [self.channel_1]
        self.factory.master_mr.requested_hash[b'1234'] = message_request

        self.factory.request_full_message(mrData)

        # We should leave channel_1 alone, but we ask channel_2 for the Message.
        self.channel_1.send.assert_not_called()
        self.channel_2.send.assert_called_once()

        # We use reactor.callLater() to schedule a call to request_full_message() again in the future.
        # So if this peer doesn't respond, when this function is next called again, it will ignore this peer
        # because of already_requested_peers and use the next one in peers_list.
        m_reactor.callLater.assert_called_once()

    def test_request_full_message_we_already_have_this_message(self, m_reactor, m_logger):
        # The local node already has this message!
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL, hash=b'1234')
        self.factory.master_mr._hash_msg[b'1234'] = Mock(autospec=Message)
        message_request = MessageRequest()
        message_request.peers_connection_list.append(self.channel_1)
        self.factory.master_mr.requested_hash[b'1234'] = message_request

        self.factory.request_full_message(mrData)

        # Because we already have this message, channel_1 is left alone.
        self.channel_1.send.assert_not_called()
        # Also, this hash should no longer appear in the Master MessageReceipt.
        self.assertIsNone(self.factory.master_mr.requested_hash.get(b'1234'))

    def test_request_full_message_no_peer_could_provide_full_message(self, m_reactor, m_logger):
        """
        If this happens, we should forget about the MessageReceipt and its hash completely.
        Optionally punish peers.
        """
        # The local node does not already have this message.
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL, hash=b'1234')

        # No idea where we can get this Message from. We haven't requested this Message from anybody.
        message_request = MessageRequest()
        message_request.peers_connection_list = []
        message_request.already_requested_peers = []
        self.factory.master_mr.requested_hash[b'1234'] = message_request

        self.factory.request_full_message(mrData)

        self.channel_1.send.assert_not_called()
        self.assertIsNone(self.factory.master_mr.requested_hash.get(b'1234'))

        # Now that we've completely forgotten about the MessageReceipt and its hash,
        # the case in test_request_full_message_we_have_already_forgotten_about_this_hash() will happen.

    def test_request_full_message_we_have_already_forgotten_about_this_hash(self, m_reactor, m_logger):
        """
        If we couldn't download the full Message from any peer, then we would've forgotten about this MessageReceipt
        and its hash.
        The next time request_full_message() is called, we find that we have forgotten about the MR and thus do nothing.
        """
        mrData = qrllegacy_pb2.MRData(type=qrllegacy_pb2.LegacyMessage.SL, hash=b'1234')

        self.factory.request_full_message(mrData)

        self.channel_1.send.assert_not_called()
        m_reactor.callLater.assert_not_called()

    def test_broadcast(self, m_reactor, m_logger):
        # broadcast msg_type is qrllegacy_pb2.LegacyMessage
        self.factory.broadcast(qrllegacy_pb2.LegacyMessage.TX, b'1234')
        self.channel_1.send.assert_called_once()
        self.channel_2.send.assert_called_once()
        self.channel_3.send.assert_called_once()

    def test_broadcast_does_not_broadcast_to_peers_known_to_have_the_mr(self, m_reactor, m_logger):
        message_request = MessageRequest()
        message_request.peers_connection_list = [self.channel_2, self.channel_3]
        self.factory.master_mr.requested_hash[b'1234'] = message_request
        self.factory.broadcast(qrllegacy_pb2.LegacyMessage.SL, b'1234')
        self.channel_1.send.assert_called_once()
        self.channel_2.send.assert_not_called()
        self.channel_3.send.assert_not_called()

    def test_broadcast_tx(self, m_reactor, m_logger):
        # broadcast_tx() should handle all Transaction Types
        self.factory.broadcast_tx(MessageTransaction())
        self.factory.broadcast_tx(TransferTransaction())
        self.factory.broadcast_tx(TokenTransaction())
        self.factory.broadcast_tx(TransferTokenTransaction())
        self.factory.broadcast_tx(SlaveTransaction())
        with self.assertRaises(ValueError):
            m_tx = Mock(autospec=TransferTransaction, txhash=bhstr2bin('deadbeef'))
            self.factory.broadcast_tx(m_tx)

    def test_broadcast_block(self, m_reactor, m_logger):
        """
        Not much to test here, other than that it works
        """
        tx = Mock(autospec=TransferTransaction, public_key=b'1234')
        b = Mock(autospec=Block, transactions=[tx], headerhash=bhstr2bin('1234'), block_number=1,
                 prev_headerhash=bhstr2bin('deadbeef'))
        self.factory.broadcast_block(b)

    def test_get_random_peer(self, m_reactor, m_logger):
        """
        1. Figures out max cumulative difficulty from what it knows about other peers
        2. Fills best_connection_ids with peers that have the max_cumulative_difficulty
        3. selected_peer_connections is simply a list of P2PProtocols that correspond to the IPs in best_connection_ids
        """
        self.factory.update_peer_blockheight(make_address('1.1.1.1'), 5, b'555555', StringToUInt256('5'))
        result = self.factory.get_random_peer()
        self.assertEqual(result, self.channel_1)

        # Even though block_number is the same, it will pick channel_2 because the difficulty is higher.
        self.factory.update_peer_blockheight(make_address('2.2.2.2'), 5, b'555555', StringToUInt256('6'))
        result = self.factory.get_random_peer()
        self.assertEqual(result, self.channel_2)

        # Now it should either return channel_2 or channel_3
        self.factory.update_peer_blockheight(make_address('3.3.3.3'), 5, b'555555', StringToUInt256('6'))
        result = self.factory.get_random_peer()
        self.assertIn(result, [self.channel_2, self.channel_3])

    def test_get_random_peer_no_peers(self, m_reactor, m_logger):
        """
        If all peers have max cumulative difficulty 0, why bother returning them?
        """
        self.factory.update_peer_blockheight('1.1.1.1:9000', 5, b'555555', StringToUInt256('0'))
        self.factory.update_peer_blockheight('2.2.2.2:9000', 5, b'555555', StringToUInt256('0'))
        self.factory.update_peer_blockheight('3.3.3.3:9000', 5, b'555555', StringToUInt256('0'))

        result = self.factory.get_random_peer()
        self.assertIsNone(result)

    def test_request_peer_blockheight(self, m_reactor, m_logger):
        self.factory.request_peer_blockheight()
        self.channel_1.send.assert_called_once()
        self.channel_2.send.assert_called_once()
        self.channel_3.send.assert_called_once()

        # 0 means that we are asking for the blockheight, not telling them ours.
        self.assertEqual(0, self.channel_1.send.call_args[0][0].bhData.block_number)

    def test_add_unprocessed_txn(self, m_reactor, m_logger):
        """
        This function is very simple. It simply tries to add the tx to the tx_pool.
        If that works, then it tries to start the txn_processor if it isn't already started.
        If the tx_pool can't be added to, there's nothing we can do and return False.
        """
        self.factory._chain_manager = Mock(autospec=ChainManager)
        self.factory._chain_manager.tx_pool.update_pending_tx_pool.return_value = True
        m_tx = Mock(autospec=TransferTransaction)
        m_tx.fee = 0

        self.assertFalse(self.factory._txn_processor_running)
        # It worked, and a TxnProcessor was started
        result = self.factory.add_unprocessed_txn(m_tx, '1.1.1.1')
        self.assertTrue(result)
        self.assertTrue(self.factory._txn_processor_running)

    def test_add_unprocessed_txn_txnprocessor_already_running(self, m_reactor, m_logger):
        """
        If the txnprocessor is already running, return True as usual.
        """
        self.factory._chain_manager = Mock(autospec=ChainManager)
        self.factory._chain_manager.tx_pool.update_pending_tx_pool.return_value = True
        self.factory._txn_processor_running = True
        m_tx = Mock(autospec=TransferTransaction)
        m_tx.fee = 0

        # It worked
        result = self.factory.add_unprocessed_txn(m_tx, '1.1.1.1')
        self.assertTrue(result)

    def test_add_unprocessed_txn_add_to_txpool_failed(self, m_reactor, m_logger):
        """
        If we couldn't add to txpool, don't start the txnprocessor. And return False.
        """
        self.factory._chain_manager = Mock(autospec=ChainManager)
        self.factory._chain_manager.tx_pool.update_pending_tx_pool.return_value = False
        m_tx = Mock(autospec=TransferTransaction)
        m_tx.fee = 0

        result = self.factory.add_unprocessed_txn(m_tx, '1.1.1.1')
        self.assertFalse(result)


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
@patch('qrl.core.p2p.p2pfactory.logger', autospec=logger, name="Mock Logger")
@patch('qrl.core.p2p.p2pfactory.reactor', autospec=reactor, name="My Mock Reactor")
class TestP2PFactoryCompareAndSync(TestCase):
    def setUp(self):
        def replacement_get_block_by_number(i):
            return self.blocks[i - 1]

        port = '9000'
        self.m_qrlnode = Mock(autospec=QRLNode, name='Fake QRLNode')
        self.factory = P2PFactory(chain_manager=ChainManager(state=Mock(autospec=State)), sync_state=None,
                                  qrl_node=self.m_qrlnode)

        self.factory.peer_fetch_block = Mock(autospec=P2PFactory.peer_fetch_block)
        self.factory._chain_manager.get_block_by_number = replacement_get_block_by_number

        self.channel_1 = Mock(autospec=P2PProtocol, name='mock Channel 1', peer_ip='1.1.1.1', peer_port=port)
        self.factory.add_connection(self.channel_1)

        self.blocks = [
            Mock(autospec=Block, name='0th Block', block_number=1, headerhash=bhstr2bin('123456')),
            Mock(autospec=Block, name='1st Block', block_number=2, headerhash=bhstr2bin('7890ab')),
            Mock(autospec=Block, name='2nd Block', block_number=3, headerhash=bhstr2bin('deadbeef'))
        ]
        self.node_header_hash = qrl_pb2.NodeHeaderHash(
            block_number=1,
            headerhashes=[bhstr2bin('123456'), bhstr2bin('7890ab'), bhstr2bin('deadbeef')]
        )

    def test_compare_and_sync_no_fork(self, m_reactor, m_logger):
        """
        compare_and_sync() looks for forks by comparing headerhashes in the peer's NodeHeaderHash and the node's blocks.
        There is no fork
        """

        # If it finds out we're on the last block of the NodeHeaderHash list, then it doesn't ask the peer for more blocks.
        self.factory._chain_manager._last_block = self.blocks[-1]
        self.factory.compare_and_sync(self.channel_1, self.node_header_hash)
        self.factory.peer_fetch_block.assert_not_called()

        # If we are in the middle of the NodeHeaderHash list, it asks for the next block.
        self.factory._chain_manager._last_block = self.blocks[0]
        self.factory.compare_and_sync(self.channel_1, self.node_header_hash)
        self.factory.peer_fetch_block.assert_called_once()

    def test_compare_and_sync_detect_fork(self, m_reactor, m_logger):
        """
        There is a fork at block_number 2.
        peer_fetch_block() should be called.
        """
        # Mess with the expected headerhash value
        self.node_header_hash = qrl_pb2.NodeHeaderHash(
            block_number=1,
            headerhashes=[bhstr2bin('123456'), bhstr2bin('000000'), bhstr2bin('deadbeef')]
        )
        # Set our state as being on the 2nd block of the NodeHeaderHash
        self.factory._chain_manager._last_block = self.blocks[1]

        self.factory.compare_and_sync(self.channel_1, self.node_header_hash)

        self.factory.peer_fetch_block.assert_called_once()

    def test_compare_and_sync_nonsense_block_number(self, m_reactor, m_logger):
        """
        The NodeHeaderHash has a block_number, which indicates the block_number of the the first headerhash.
        To be processing a block with a block_number less than NodeHeaderHash.block_number makes no sense.
        """
        # Mess with Block 2's block_number
        self.blocks[1].block_number = 0

        # Set our state as being on the 2nd block of the NodeHeaderHash
        self.factory._chain_manager.last_block.return_value = self.blocks[1]
        self.factory.compare_and_sync(self.channel_1, self.node_header_hash)

        self.factory.peer_fetch_block.assert_not_called()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
@patch('qrl.core.p2p.p2pfactory.logger', autospec=logger, name="Mock Logger")
@patch('qrl.core.p2p.p2pfactory.reactor', autospec=reactor, name="My Mock Reactor")
class TestP2PFactoryPeerFetchBlock(TestCase):
    def setUp(self):
        port = '9000'
        self.m_qrlnode = Mock(autospec=QRLNode, name='Fake QRLNode')
        self.channel_1 = Mock(autospec=P2PProtocol, name='mock Channel 1', peer_ip='1.1.1.1', peer_port=port)
        self.channel_2 = Mock(autospec=P2PProtocol, name='mock Channel 2', peer_ip='2.2.2.2', peer_port=port)
        self.channel_3 = Mock(autospec=P2PProtocol, name='mock Channel 3', peer_ip='3.3.3.3', peer_port=port)

        self.factory = P2PFactory(chain_manager=ChainManager(state=Mock(autospec=State)), sync_state=None,
                                  qrl_node=self.m_qrlnode)
        self.factory.pow = Mock(autospec=POW)

        self.m_qrlnode.is_banned.return_value = False
        self.factory.add_connection(self.channel_1)
        self.factory.add_connection(self.channel_2)
        self.factory.add_connection(self.channel_3)

        self.factory._target_channel = self.channel_1
        self.factory.is_syncing_finished = Mock(return_value=False, autospec=P2PFactory.is_syncing_finished)
        self.factory._target_node_header_hash = qrl_pb2.NodeHeaderHash(
            block_number=1,
            headerhashes=[bhstr2bin('123456'), bhstr2bin('deadbeef'), bhstr2bin('abcdef')]
        )
        self.factory._last_requested_block_number = 1

    def test_peer_fetch_block_we_dont_already_have_the_block(self, m_reactor, m_logger):
        """
        Given a peer's NodeHeaderHash (inventory), peer_fetch_block() tries to find a corresponding block in the node's
        chain. If it can't find it then it sends a fetch_block Message (P2PProtocol.send_fetch_block())
        """
        self.factory._chain_manager._state.get_block.return_value = None

        self.factory.peer_fetch_block()

        self.channel_1.send_fetch_block.assert_called_once_with(1)

    def test_peer_fetch_block_we_already_have_the_block(self, m_reactor, m_logger):
        """
        If peer_fetch_block() finds a corresponding block in the node's chain, then it keeps asking the node's local
        chain for newer blocks until
        1. the node doesn't have any newer blocks OR
        2. we've reached the end of the peer's NodeHeaderHash.
        Then it will ask the peer for the next block after that.
        """
        self.factory._chain_manager._state.get_block.return_value = Block()

        self.factory.peer_fetch_block()

        self.assertEqual(self.factory._chain_manager._state.get_block.call_count, 3)
        self.channel_1.send_fetch_block.assert_called_once_with(3)

    def test_peer_fetch_block_we_are_synced(self, m_reactor, m_logger):
        """
        If is_syncing_finished() is True, then let's not ask for more blocks.
        """
        self.factory._chain_manager._state.get_block.return_value = Block()
        self.factory.is_syncing_finished.return_value = True

        self.factory.peer_fetch_block()

        self.channel_1.send_fetch_block.assert_not_called()

    def test_peer_fetch_block_block_not_found_and_retry(self, m_reactor, m_logger):
        """
        If we can't find the blocks that the Peer's NodeHeaderHash indicated, and retry >= 5, ban the peer.
        Assume we are synced.
        """
        self.factory._chain_manager._state.get_block.return_value = None

        self.factory.peer_fetch_block(retry=5)

        self.m_qrlnode.peer_manager.ban_channel.assert_called_once_with(self.channel_1)
        self.factory.is_syncing_finished.assert_called_once_with(force_finish=True)


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
@patch('qrl.core.p2p.p2pfactory.logger', autospec=logger, name="Mock Logger")
@patch('qrl.core.p2p.p2pfactory.reactor', autospec=reactor, name="My Mock Reactor")
class TestP2PFactoryBlockReceived(TestCase):
    def setUp(self):
        port = '9000'
        self.m_qrlnode = Mock(autospec=QRLNode, name='Fake QRLNode')
        self.channel_1 = Mock(autospec=P2PProtocol, name='mock Channel 1', peer_ip='1.1.1.1', peer_port=port)
        self.channel_2 = Mock(autospec=P2PProtocol, name='mock Channel 2', peer_ip='2.2.2.2', peer_port=port)
        self.channel_3 = Mock(autospec=P2PProtocol, name='mock Channel 3', peer_ip='3.3.3.3', peer_port=port)

        self.factory = P2PFactory(chain_manager=Mock(autospec=ChainManager), sync_state=None, qrl_node=self.m_qrlnode)
        self.factory.pow = Mock(autospec=POW)

        self.m_qrlnode.is_banned.return_value = False
        self.factory.add_connection(self.channel_1)
        self.factory.add_connection(self.channel_2)
        self.factory.add_connection(self.channel_3)

        # The peer has two blocks. It has sent a list of their hashes, and block_number indicates that the first hash
        # in the list is for block_number 1.
        self.factory._target_node_header_hash = qrl_pb2.NodeHeaderHash(
            block_number=1,
            headerhashes=[bhstr2bin('123456'), bhstr2bin('deadbeef')]
        )

        # This mocking ensures that the Block gets added to the Chain, and that the next block is requested.
        self.factory._target_peer = self.channel_1
        self.factory._last_requested_block_number = 1
        self.factory._chain_manager.add_block.return_value = True
        self.factory.peer_fetch_block = Mock(autospec=P2PFactory.peer_fetch_block)

    def tearDown(self):
        self.factory.remove_connection(self.channel_1)
        self.factory.remove_connection(self.channel_2)
        self.factory.remove_connection(self.channel_3)

    def test_block_received(self, m_reactor, m_logger):
        """
        P2PChainManager.handle_push_block() simply creates the Block from the incoming Protobuf data, and throws an
        error if it can't.
        But this function is the one that actually:
        1. checks that the block came from the peer we were talking to
        2. checks that the block is the one we requested
        3. validates the block
        4. requests the next block (since we are in a syncing scenario)
        """
        m_reactor.download_monitor = Mock()
        # The peer has sent the whole block that corresponds to block_number 1.
        block = Mock(autospec=Block, block_number=1, headerhash=bhstr2bin('123456'))
        block.validate.return_value = True

        self.factory._target_channel = self.channel_1
        self.factory.block_received(self.channel_1, block)

        self.factory._chain_manager.add_block.assert_called_once()
        # After all this, the node should ask for the next block.
        self.factory.peer_fetch_block.assert_called_once()

        # After the peer sends the last block, we should not ask for any more blocks.
        self.factory._chain_manager.add_block.reset_mock()
        self.factory.peer_fetch_block.reset_mock()
        block_2 = Mock(autospec=Block, block_number=2, headerhash=bhstr2bin('deadbeef'))
        block.validate.return_value = True

        self.factory.block_received(self.channel_1, block_2)

        self.factory._chain_manager.add_block.assert_called_once()
        self.assertIsNone(self.factory._target_channel)
        self.factory.peer_fetch_block.assert_not_called()

    def test_block_received_suspend_mining_when_we_just_updated_chain(self, m_reactor, m_logger):
        """
        If we've just updated the chain with a new block, start mining a bit later, not now.
        """
        m_reactor.download_monitor = Mock()
        self.factory._chain_manager.last_block.headerhash = bhstr2bin('123456')
        block = Mock(autospec=Block, block_number=1, headerhash=bhstr2bin('123456'))
        self.factory.block_received(self.channel_1, block)
        self.assertNotEqual(self.factory.pow.suspend_mining_timestamp, 0)

    def test_block_received_wrong_peer(self, m_reactor, m_logger):
        """
        If the incoming Block didn't come from the peer we were talking to, don't process (ignore) it.
        """
        m_reactor.download_monitor = Mock()
        block = Mock(autospec=Block, block_number=1, headerhash=bhstr2bin('123456'))
        block.validate.return_value = True

        self.factory._target_channel = self.channel_2

        self.factory.block_received(self.channel_1, block)

        self.factory._chain_manager.add_block.assert_not_called()
        self.factory.peer_fetch_block.assert_not_called()

    def test_block_received_wrong_block_idx(self, m_reactor, m_logger):
        """
        If the incoming block_number is not the one we requested, don't process it.
        """
        m_reactor.download_monitor = Mock()
        block = Mock(autospec=Block, block_number=2, headerhash=bhstr2bin('123456'))
        block.validate.return_value = True

        self.factory.block_received(self.channel_1, block)

        self.factory._chain_manager.add_block.assert_not_called()
        self.factory.peer_fetch_block.assert_not_called()

    def test_block_received_wrong_block_headerhash(self, m_reactor, m_logger):
        """
        The node should already know which block_number should have which headerhash.
        """
        m_reactor.download_monitor = Mock()
        block = Mock(autospec=Block, block_number=1, headerhash=bhstr2bin('deadbeef'))
        block.validate.return_value = True

        self.factory.block_received(self.channel_1, block)

        self.factory._chain_manager.add_block.assert_not_called()
        self.factory.peer_fetch_block.assert_not_called()

    def test_block_received_block_fails_validation(self, m_reactor, m_logger):
        """
        Somehow the block fails to validate. Then it shouldn't be added to the chain.
        """
        m_reactor.download_monitor = Mock()
        block = Mock(autospec=Block, block_number=1, headerhash=bhstr2bin('123456'))
        block.validate.return_value = False

        self.factory.block_received(self.channel_1, block)

        self.factory._chain_manager.add_block.assert_not_called()
        self.factory.peer_fetch_block.assert_not_called()

    def test_block_received_adding_block_fails(self, m_reactor, m_logger):
        """
        If the block couldn't be added to the chain for any reason, don't ask for the next block.
        In fact, don't even run is_syncing_finished(), for it might mess up our current state.
        """
        m_reactor.download_monitor = Mock()
        block = Mock(autospec=Block, block_number=1, headerhash=bhstr2bin('123456'))
        block.validate.return_value = True
        self.factory._chain_manager.add_block.return_value = False
        self.factory.is_syncing_finished = Mock(autospec=P2PFactory.is_syncing_finished)

        self.factory.block_received(self.channel_1, block)

        self.factory.peer_fetch_block.assert_not_called()
        self.factory.is_syncing_finished.assert_not_called()
