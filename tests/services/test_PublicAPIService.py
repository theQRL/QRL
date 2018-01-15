# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import pytest
from grpc import ServicerContext
from mock import Mock, MagicMock
from pyqrllib.pyqrllib import str2bin

from qrl.core.misc import logger
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.AddressState import AddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.Block import Block
from qrl.core.Transaction import TransferTransaction
from qrl.core.node import SyncState, POW
from qrl.core.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.core.State import State
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from qrl.core import config
from tests.misc.helper import qrladdress, get_alice_xmss

logger.initialize_default()


class TestPublicAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI, self).__init__(*args, **kwargs)

    def test_getNodeState(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.sync_state = SyncState()
        p2p_factory.connections = 23
        p2p_factory.pow = Mock()

        chain_manager = Mock(spec=ChainManager)
        chain_manager.height = 0

        qrlnode = QRLNode(db_state)
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow

        service = PublicAPIService(qrlnode)
        node_state = service.GetNodeState(request=qrl_pb2.GetNodeStateReq, context=None)

        # self.assertEqual(__version__, node_state.info.version)  # FIXME
        self.assertEqual(qrl_pb2.NodeInfo.UNSYNCED, node_state.info.state)
        self.assertEqual(23, node_state.info.num_connections)
        # self.assertEqual("testnet", node_state.info.network_id)  # FIXME

    def test_getKnownPeers(self):
        db_state = Mock(spec=State)
        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.sync_state = SyncState()
        p2p_factory.connections = 23
        p2p_factory.pow = Mock()

        chain_manager = Mock(spec=ChainManager)
        chain_manager.height = 0

        qrlnode = QRLNode(db_state)
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow
        qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)
        response = service.GetKnownPeers(request=qrl_pb2.GetKnownPeersReq, context=None)

        self.assertEqual(2, len(response.known_peers))
        self.assertEqual('127.0.0.1', response.known_peers[0].ip)
        self.assertEqual('192.168.1.1', response.known_peers[1].ip)

        logger.info(response)

    def test_getStats(self):
        db_state = Mock(spec=State)
        db_state.total_coin_supply = MagicMock(return_value=1000)

        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.sync_state = SyncState()
        p2p_factory.connections = 23
        p2p_factory.pow = Mock()

        chain_manager = Mock(spec=ChainManager)
        chain_manager.height = 0
        chain_manager.get_last_block = MagicMock(return_value=GenesisBlock())
        chain_manager.get_block_by_number = MagicMock(return_value=None)
        chain_manager.state = db_state

        qrlnode = QRLNode(db_state)
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow

        service = PublicAPIService(qrlnode)
        stats = service.GetStats(request=qrl_pb2.GetStatsReq, context=None)

        # self.assertEqual(__version__, stats.node_info.version)  # FIXME

        self.assertEqual(qrl_pb2.NodeInfo.UNSYNCED, stats.node_info.state)
        self.assertEqual(23, stats.node_info.num_connections)
        # self.assertEqual("testnet", stats.node_info.network_id)  # FIXME

        self.assertEqual(0, stats.epoch)
        self.assertEqual(0, stats.uptime_network)

        self.assertEqual(0, stats.block_last_reward)
        self.assertEqual(0, stats.block_time_mean)
        self.assertEqual(0, stats.block_time_sd)

        self.assertEqual(105000000, stats.coins_total_supply)
        self.assertEqual(1000, stats.coins_emitted)

        logger.info(stats)

    def test_getAddressState(self):
        db_state = Mock(spec=State)

        db_state.get_address = MagicMock(return_value=AddressState.create(address=b'Q' + sha256(b'address'),
                                                                          nonce=25,
                                                                          balance=10,
                                                                          ots_bitfield=[
                                                                                           b'\x00'] * config.dev.ots_bitfield_size,
                                                                          tokens=dict()))

        p2p_factory = Mock(spec=P2PFactory)
        chain_manager = ChainManager(db_state)

        qrlnode = QRLNode(db_state)
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetAddressStateReq()
        response = service.GetAddressState(request=request, context=context)
        context.set_code.assert_called()
        context.set_details.assert_called()

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetAddressStateReq()
        request.address = get_alice_xmss().get_address()
        response = service.GetAddressState(request=request, context=context)
        context.set_code.assert_not_called()

        self.assertEqual(b'Q' + sha256(b'address'), response.state.address)
        self.assertEqual(25, response.state.nonce)
        self.assertEqual(10, response.state.balance)
        self.assertEqual([b'\x00'] * config.dev.ots_bitfield_size, response.state.ots_bitfield)
        self.assertEqual([], response.state.transaction_hashes)

    @pytest.mark.skip(reason="Temporarily skipping test")
    def test_getObject(self):
        SOME_ODD_HASH = sha256(b'this should not be found')
        SOME_ADDR1 = b'Q' + sha256(b'address1')
        SOME_ADDR2 = b'Q' + sha256(b'address2')

        db_state = Mock(spec=State)

        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.pow = Mock(spec=POW)

        chain_manager = Mock(spec=ChainManager)
        chain_manager.tx_pool = Mock()
        chain_manager.tx_pool.transaction_pool = []

        qrlnode = QRLNode(db_state)
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow
        qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        context.set_details.assert_not_called()
        self.assertFalse(response.found)

        # Find an address
        db_state.get_address = MagicMock(return_value=AddressState.create(address=SOME_ADDR1,
                                                                          nonce=25,
                                                                          balance=10,
                                                                          ots_bitfield=[
                                                                                           b'\x00'] * config.dev.ots_bitfield_size,
                                                                          tokens=dict()))
        db_state.get_address_tx_hashes = MagicMock(return_value=[sha256(b'0'), sha256(b'1')])

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = SOME_ODD_HASH
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertFalse(response.found)

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = SOME_ADDR1
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertTrue(response.found)
        self.assertIsNotNone(response.address_state)

        self.assertEqual(SOME_ADDR1, response.address_state.address)
        self.assertEqual(25, response.address_state.nonce)
        self.assertEqual(10, response.address_state.balance)
        self.assertEqual([sha256(b'a'), sha256(b'b')], response.address_state.pubhashes)
        self.assertEqual([sha256(b'0'), sha256(b'1')], response.address_state.transaction_hashes)

        # Find a transaction
        db_state.address_used = MagicMock(return_value=False)
        tx1 = TransferTransaction.create(addr_to=SOME_ADDR2,
                                         amount=125,
                                         fee=19,
                                         xmss_pk=sha256(b'pk'))

        chain_manager.tx_pool.transaction_pool = [tx1]

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = tx1.txhash
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertTrue(response.found)
        self.assertIsNotNone(response.transaction)
        self.assertEqual(qrl_pb2.Transaction.TRANSFER, response.transaction.type)
        self.assertEqual(SOME_ADDR1, response.transaction.addr_from)
        self.assertEqual(sha256(b'pk'), response.transaction.public_key)
        self.assertEqual(tx1.txhash, response.transaction.transaction_hash)
        self.assertEqual(13, response.transaction.ots_key)
        self.assertEqual(b'', response.transaction.signature)

        self.assertEqual(SOME_ADDR2, response.transaction.transfer.addr_to)
        self.assertEqual(125, response.transaction.transfer.amount)
        self.assertEqual(19, response.transaction.transfer.fee)

        # Find a block
        chain_manager.get_block = MagicMock(
            return_value=Block.create(mining_nonce=10,
                                      block_number=1,
                                      prevblock_headerhash=sha256(b'reveal'),
                                      transactions=[],
                                      signing_xmss=get_alice_xmss(),
                                      nonce=1))

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = bytes(str2bin('1'))
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertTrue(response.found)
        self.assertIsNotNone(response.block)
        self.assertEqual(1, response.block.header.block_number)

    @pytest.mark.skip(reason="Temporarily skipping test")
    def test_getLatestData(self):
        blocks = []
        txs = []
        for i in range(1, 4):
            for j in range(1, 3):
                txs.append(TransferTransaction.create(addr_from=get_alice_xmss().get_address(),
                                                      addr_to=qrladdress('dest'),
                                                      amount=i * 100 + j,
                                                      fee=j,
                                                      xmss_pk=get_alice_xmss().pk()))

            blocks.append(Block.create(mining_nonce=10,
                                       block_number=i,
                                       prevblock_headerhash=sha256(b'reveal'),
                                       transactions=txs,
                                       signing_xmss=get_alice_xmss(),
                                       nonce=i))

        txpool = []
        for j in range(10, 15):
            txpool.append(TransferTransaction.create(addr_from=get_alice_xmss().get_address(),
                                                     addr_to=qrladdress('dest'),
                                                     amount=1000 + j,
                                                     fee=j,
                                                     xmss_pk=get_alice_xmss().pk()))

        db_state = Mock(spec=State)

        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.pow = Mock(spec=POW)

        chain_manager = Mock(spec=ChainManager)
        chain_manager.tx_pool = Mock()
        chain_manager.tx_pool.transaction_pool = txpool

        chain_manager.get_block = Mock()
        chain_manager.get_block.side_effect = blocks
        chain_manager.height = len(blocks)

        qrlnode = QRLNode(db_state)
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow

        service = PublicAPIService(qrlnode)
        context = Mock(spec=ServicerContext)

        request = qrl_pb2.GetLatestDataReq(filter=qrl_pb2.GetLatestDataReq.ALL,
                                           offset=1,
                                           quantity=3)

        response = service.GetLatestData(request=request, context=context)

        context.set_code.assert_not_called()
        context.set_details.assert_not_called()

        # Verify blockheaders
        self.assertEqual(2, len(response.blockheaders))
        self.assertEqual(1, response.blockheaders[0].header.block_number)
        self.assertEqual(2, response.blockheaders[1].header.block_number)

        # Verify transactions
        self.assertEqual(3, len(response.transactions))
        self.assertEqual(1, response.transactions[0].transfer.fee)
        self.assertEqual(2, response.transactions[1].transfer.fee)
        self.assertEqual(1, response.transactions[2].transfer.fee)

        # 302 should have been skipped
        self.assertEqual(301, response.transactions[0].transfer.amount)
        self.assertEqual(202, response.transactions[1].transfer.amount)
        self.assertEqual(201, response.transactions[2].transfer.amount)

        # Verify transactions_unconfirmed
        self.assertEqual(3, len(response.transactions_unconfirmed))
        self.assertEqual(1013, response.transactions_unconfirmed[0].transfer.amount)
        self.assertEqual(1012, response.transactions_unconfirmed[1].transfer.amount)
        self.assertEqual(1011, response.transactions_unconfirmed[2].transfer.amount)
