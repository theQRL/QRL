# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, patch
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.p2p.p2pChainManager import P2PChainManager
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.p2p.p2pprotocol import P2PProtocol
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2, qrllegacy_pb2

logger.initialize_default()


def make_message(**kwargs):
    return qrllegacy_pb2.LegacyMessage(**kwargs)


@patch('qrl.core.p2p.p2pChainManager.logger')
class TestP2PChainManager(TestCase):
    def setUp(self):
        self.manager = P2PChainManager()
        self.channel = Mock(autospec=P2PProtocol, addr_remote='1.1.1.1')
        self.channel.factory = Mock(autospec=P2PFactory)
        self.channel.factory.master_mr = Mock(autospec=MessageReceipt)

    def test_new_channel_registers_with_observables(self, m_logger):
        self.manager.new_channel(self.channel)
        self.channel.register.assert_called()

    def test_handle_fetch_block(self, m_logger):
        """
        1. A peer has sent a request for a block.
        2. This function serves the block in response to that request.
        :return:
        """
        self.channel.factory.chain_height = 10
        self.channel.factory.get_block_by_number.return_value = Mock(autospec=Block, pbdata=qrl_pb2.Block())
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.FB, fbData=qrllegacy_pb2.FBData(index=1))
        self.manager.handle_fetch_block(self.channel, msg)

        self.channel.send.assert_called()

    def test_handle_fetch_block_bad_height(self, m_logger):
        """
        If the peer has sent a request for a block which we don't have, nothing should happen.
        :return:
        """
        self.channel.factory.chain_height = 10
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.FB, fbData=qrllegacy_pb2.FBData(index=100))
        self.manager.handle_fetch_block(self.channel, msg)

        self.channel.send.assert_not_called()

    def test_handle_push_block(self, m_logger):
        """
        1. This node has requested a peer to send us its MessageReceipts
        2. The node has received a list of Block headers
        3. The node has requested a specific block.
        4. The peer sends the new block, which is handled by this function?
        :return:
        """
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.PB, pbData=qrllegacy_pb2.PBData(block=qrl_pb2.Block()))
        self.manager.handle_push_block(self.channel, msg)

        self.channel.factory.block_received.assert_called()

    @patch('qrl.core.p2p.p2pChainManager.Block')
    def test_handle_push_block_bad_block(self, m_Block, m_logger):
        """
        If the Block couldn't be constructed from the Protobuf data, nothing should happen.
        (including disconnecting the peer? dunno)
        :return:
        """
        # Case 1: Block() raises an Exception
        m_Block.side_effect = Exception
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.PB, pbData=qrllegacy_pb2.PBData(block=qrl_pb2.Block()))
        self.manager.handle_push_block(self.channel, msg)

        self.channel.factory.block_received.assert_not_called()

        # Case 2: no protobuf data was in the message.
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.PB)
        self.manager.handle_push_block(self.channel, msg)

        self.channel.factory.block_received.assert_not_called()

    def test_handle_block(self, m_logger):
        """
        1. A peer has found a new block. It broadcasts the MessageReceipt for that block.
        2. This node finds that it hasn't got that block yet, so it requests that block.
        3. The peer sends the new block, which is handled by this function.
        :return:
        """
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.BK,
                           block=qrl_pb2.Block(),
                           mrData=qrllegacy_pb2.MRData()
                           )
        self.manager.handle_block(self.channel, msg)
        self.channel.factory.master_mr.register.assert_called()

        # But if we didn't request this block, we shouldn't process it.
        self.channel.factory.master_mr.register.reset_mock()
        self.channel.factory.master_mr.isRequested.return_value = False

        self.manager.handle_block(self.channel, msg)
        self.channel.factory.master_mr.register.assert_not_called()

    @patch('qrl.core.p2p.p2pChainManager.Block')
    def test_handle_block_bad_block(self, m_Block, m_logger):
        """
        If the block couldn't be constructed from the message, the function should return without doing
        anything else.
        :return:
        """
        m_Block.side_effect = Exception
        msg = make_message(func_name=qrllegacy_pb2.LegacyMessage.BK,
                           block=qrl_pb2.Block(),
                           mrData=qrllegacy_pb2.MRData()
                           )
        self.manager.handle_block(self.channel, msg)
        self.channel.factory.master_mr.register.assert_not_called()
        self.channel.factory.pow.pre_block_logic.assert_not_called()

    def test_handle_block_height_incoming_request(self, m_logger):
        """
        handle_block_height(), unlike other handlers in this class, deals with requests and sends out responses
        to requests, all in the same function!
        If the incoming message.bhData.block_number is 0, this means that the peer wants to know our block height.
        If the incoming message.bhData.block_number is not 0, this means that we should update our knowledge of the
        peer's blockheight.
        """
        self.channel.factory = Mock(
            last_block=Mock(autospec=Block, block_number=5, headerhash=b''),
            get_cumulative_difficulty=Mock(return_value=(0,)))

        incoming_request = make_message(func_name=qrllegacy_pb2.LegacyMessage.BH,
                                        bhData=qrl_pb2.BlockHeightData(block_number=0))

        self.manager.handle_block_height(self.channel, incoming_request)

        self.channel.send.assert_called()
        self.channel.factory.update_peer_blockheight.assert_not_called()

    def test_handle_block_height_incoming_request_but_node_at_blockheight_zero(self, m_logger):
        """
        If the incoming message.bhData.block_number is 0, this means that the peer wants to know our block height.
        However, if we are at blockheight 0 ourselves, we shamefully reply with silence.
        """
        self.channel.factory = Mock(
            last_block=Mock(autospec=Block, block_number=0, headerhash=b''),
            get_cumulative_difficulty=Mock(return_value=(0,)))

        incoming_request = make_message(func_name=qrllegacy_pb2.LegacyMessage.BH,
                                        bhData=qrl_pb2.BlockHeightData(
                                            block_number=0,
                                        ))
        self.manager.handle_block_height(self.channel, incoming_request)

        self.channel.send.assert_not_called()
        self.channel.factory.update_peer_blockheight.assert_not_called()

    def test_handle_block_height_incoming_information(self, m_logger):
        """
        If the incoming message.bhData.block_number is not 0, this means that we should update our knowledge of the
        peer's blockheight.
        """

        some_cumulative_difficulty = bytes(StringToUInt256('0'))
        incoming_info = make_message(func_name=qrllegacy_pb2.LegacyMessage.BH,
                                     bhData=qrl_pb2.BlockHeightData(
                                         block_number=1,
                                         block_headerhash=sha256(b'some_hash'),
                                         cumulative_difficulty=some_cumulative_difficulty
                                     ))
        self.manager.handle_block_height(self.channel, incoming_info)

        self.channel.send.assert_not_called()
        self.channel.factory.update_peer_blockheight.assert_called()

    def test_handle_node_headerhash_peer_has_no_headerhashes(self, m_logger):
        """
        This function also handles requests and responses of NodeHeaderHashes.
        A NodeHeaderHash is a list of blockhashes that a particular node has.
        If the incoming nodeHeaderHash message object has no headerhashes, let's assume the peer needs to sync and send
        a list of our headerhashes.
        """
        self.channel.factory.get_headerhashes.return_value = qrl_pb2.NodeHeaderHash()
        incoming_request = make_message(func_name=qrllegacy_pb2.LegacyMessage.HEADERHASHES,
                                        nodeHeaderHash=qrl_pb2.NodeHeaderHash(block_number=0)
                                        )
        self.manager.handle_node_headerhash(self.channel, incoming_request)
        self.channel.send.assert_called()

    def test_handle_node_headerhash_peer_has_headerhashes(self, m_logger):
        """
        This function also handles requests and responses of NodeHeaderHashes.
        A NodeHeaderHash is a list of blockhashes that a particular node has.
        If the incoming nodeHeaderHash message object has headerhashes, compare our headerhash list and possibly sync.
        """
        incoming_info = make_message(func_name=qrllegacy_pb2.LegacyMessage.HEADERHASHES,
                                     nodeHeaderHash=qrl_pb2.NodeHeaderHash(block_number=3,
                                                                           headerhashes=(b'0', b'1', b'2')))
        self.manager.handle_node_headerhash(self.channel, incoming_info)
        self.channel.factory.compare_and_sync.assert_called()
