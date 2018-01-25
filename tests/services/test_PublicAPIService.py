# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

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

        qrlnode = QRLNode(db_state, slaves=[])
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

        qrlnode = QRLNode(db_state, slaves=[])
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

        qrlnode = QRLNode(db_state, slaves=[])
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
        address_state = AddressState.create(address=b'Q' + sha256(b'address'),
                                            nonce=25,
                                            balance=10,
                                            ots_bitfield=[b'\x00'] * config.dev.ots_bitfield_size,
                                            tokens=dict(),
                                            slave_pks_access_type=dict())
        db_state.get_address = MagicMock(return_value=address_state)

        p2p_factory = Mock(spec=P2PFactory)
        chain_manager = ChainManager(db_state)

        qrlnode = QRLNode(db_state, slaves=[])
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

    def test_getObject(self):
        SOME_ODD_HASH = sha256(b'this should not be found')
        SOME_ADDR1 = b'Q6dcadae42bc451f3bc8b243c8654bcd588fff443b141a9ad2fcdbbd712ba038a0a2a83b1'
        SOME_ADDR2 = b'Q14542ca43bc801effbc398ed6703924f7287f13d3c3d6c0c6d9d5a41c246d7cc08f71c85'

        db_state = Mock(spec=State)
        db_state.get_tx_metadata = MagicMock(return_value=None)
        db_state.get_block = MagicMock(return_value=None)

        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.pow = Mock(spec=POW)

        chain_manager = ChainManager(db_state)

        qrlnode = QRLNode(db_state, slaves=[])
        qrlnode.set_chain(chain_manager)
        qrlnode._p2pfactory = p2p_factory
        qrlnode._pow = p2p_factory.pow
        qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

        service = PublicAPIService(qrlnode)

        # First try an empty request
        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        context.set_details.assert_not_called()
        self.assertFalse(response.found)

        # Some odd address
        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = SOME_ODD_HASH
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertFalse(response.found)

        # Find an address
        addr1_state = AddressState.create(address=SOME_ADDR1,
                                          nonce=25,
                                          balance=10,
                                          ots_bitfield=[b'\x00'] * config.dev.ots_bitfield_size,
                                          tokens=dict(),
                                          slave_pks_access_type=dict())
        addr1_state.transaction_hashes.append(sha256(b'0'))
        addr1_state.transaction_hashes.append(sha256(b'1'))

        db_state.get_address = MagicMock(return_value=addr1_state.pbdata)

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
        self.assertEqual([sha256(b'0'), sha256(b'1')], response.address_state.transaction_hashes)

        # Find a transaction
        db_state.address_used = MagicMock(return_value=False)
        tx1 = TransferTransaction.create(
            addr_from=SOME_ADDR1,
            addr_to=SOME_ADDR2,
            amount=125,
            fee=19,
            xmss_pk=sha256(b'pk'),
            xmss_ots_index=0)

        chain_manager.tx_pool.transaction_pool = [tx1]

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = tx1.txhash
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertTrue(response.found)
        self.assertIsNotNone(response.transaction)
        self.assertEqual(qrl_pb2.Transaction.TRANSFER, response.transaction.tx.type)
        self.assertEqual(SOME_ADDR1, response.transaction.tx.addr_from)
        self.assertEqual(sha256(b'pk'), response.transaction.tx.public_key)
        self.assertEqual(tx1.txhash, response.transaction.tx.transaction_hash)
        self.assertEqual(b'', response.transaction.tx.signature)

        self.assertEqual(SOME_ADDR2, response.transaction.tx.transfer.addr_to)
        self.assertEqual(125, response.transaction.tx.transfer.amount)
        self.assertEqual(19, response.transaction.tx.fee)

        alice_xmss = get_alice_xmss()
        # Find a block
        db_state.get_block_by_number = MagicMock(
            return_value=Block.create(mining_nonce=10,
                                      block_number=1,
                                      prevblock_headerhash=sha256(b'reveal'),
                                      transactions=[],
                                      signing_xmss=alice_xmss,
                                      master_address=alice_xmss.get_address(),
                                      nonce=1))

        context = Mock(spec=ServicerContext)
        request = qrl_pb2.GetObjectReq()
        request.query = bytes(str2bin('1'))
        response = service.GetObject(request=request, context=context)
        context.set_code.assert_not_called()
        self.assertTrue(response.found)
        self.assertIsNotNone(response.block)
        self.assertEqual(1, response.block.header.block_number)

    def test_getLatestData(self):
        blocks = []
        txs = []
        alice_xmss = get_alice_xmss()
        for i in range(1, 4):
            for j in range(1, 3):
                txs.append(TransferTransaction.create(addr_from=get_alice_xmss().get_address(),
                                                      addr_to=qrladdress('dest'),
                                                      amount=i * 100 + j,
                                                      fee=j,
                                                      xmss_pk=alice_xmss.pk(),
                                                      xmss_ots_index=alice_xmss.get_index()))

            blocks.append(Block.create(mining_nonce=10,
                                       block_number=i,
                                       prevblock_headerhash=sha256(b'reveal'),
                                       transactions=txs,
                                       signing_xmss=alice_xmss,
                                       master_address=alice_xmss.get_address(),
                                       nonce=i))

        txpool = []
        for j in range(10, 15):
            txpool.append(TransferTransaction.create(addr_from=get_alice_xmss().get_address(),
                                                     addr_to=qrladdress('dest'),
                                                     amount=1000 + j,
                                                     fee=j,
                                                     xmss_pk=get_alice_xmss().pk(),
                                                     xmss_ots_index=get_alice_xmss().get_index()))

        db_state = Mock(spec=State)
        db_state.get_tx_metadata = MagicMock(return_value=None)
        db_state.get_last_txs = MagicMock(return_value=txs)

        p2p_factory = Mock(spec=P2PFactory)
        p2p_factory.pow = Mock(spec=POW)

        chain_manager = Mock(spec=ChainManager)
        chain_manager.get_block_by_number = Mock()
        chain_manager.get_block_by_number.side_effect = blocks
        chain_manager.tx_pool = Mock()
        chain_manager.tx_pool.transaction_pool = txpool
        chain_manager.height = len(blocks)

        qrlnode = QRLNode(db_state, slaves=[])
        qrlnode.set_chain(chain_manager)
        qrlnode.get_block_from_index = MagicMock(return_value=None)

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
        self.assertEqual(3, len(response.blockheaders))
        self.assertEqual(1, response.blockheaders[0].header.block_number)
        self.assertEqual(2, response.blockheaders[1].header.block_number)
        self.assertEqual(3, response.blockheaders[2].header.block_number)

        # Verify transactions_unconfirmed
        self.assertEqual(3, len(response.transactions_unconfirmed))
        # TODO: Verify expected order
        self.assertEqual(1011, response.transactions_unconfirmed[0].tx.transfer.amount)
        self.assertEqual(1012, response.transactions_unconfirmed[1].tx.transfer.amount)
        self.assertEqual(1013, response.transactions_unconfirmed[2].tx.transfer.amount)

        # Verify transactions
        self.assertEqual(3, len(response.transactions))
        self.assertEqual(2, response.transactions[0].tx.fee)
        self.assertEqual(1, response.transactions[1].tx.fee)
        self.assertEqual(2, response.transactions[2].tx.fee)

        self.assertEqual(102, response.transactions[0].tx.transfer.amount)
        self.assertEqual(201, response.transactions[1].tx.transfer.amount)
        self.assertEqual(202, response.transactions[2].tx.transfer.amount)
