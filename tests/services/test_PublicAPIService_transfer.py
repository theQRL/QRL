# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from grpc import ServicerContext
from mock import Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.ChainManager import ChainManager
from qrl.core.State import State
from qrl.core.misc import logger
from qrl.core.node import POW
from qrl.core.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from tests.misc.helper import get_alice_xmss, set_data_dir, set_wallet_dir, get_bob_xmss

logger.initialize_default()


class TestPublicAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI, self).__init__(*args, **kwargs)

    def test_transferCoins_get_unsigned(self):
        with set_data_dir('no_data'):
            with State() as db_state:
                with set_wallet_dir("test_wallet"):
                    p2p_factory = Mock(spec=P2PFactory)
                    p2p_factory.pow = Mock(spec=POW)
                    chain_manager = ChainManager(db_state)

                    qrlnode = QRLNode(db_state, slaves=[])
                    qrlnode.set_chain_manager(chain_manager)
                    qrlnode._p2pfactory = p2p_factory
                    qrlnode._pow = p2p_factory.pow
                    qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                    service = PublicAPIService(qrlnode)

                    context = Mock(spec=ServicerContext)

                    alice = get_alice_xmss()
                    bob = get_bob_xmss()

                    request = qrl_pb2.TransferCoinsReq(
                        address_from=alice.address,
                        address_to=bob.address,
                        amount=101,
                        fee=12,
                        xmss_pk=alice.pk
                    )

                    response = service.TransferCoins(request=request, context=context)
                    context.set_code.assert_not_called()
                    context.set_details.assert_not_called()

                    self.assertIsNotNone(response)
                    self.assertIsNotNone(response.transaction_unsigned)
                    self.assertEqual('transfer', response.transaction_unsigned.WhichOneof('transactionType'))

                    self.assertEqual(alice.address, response.transaction_unsigned.addr_from)
                    self.assertEqual(12, response.transaction_unsigned.fee)
                    self.assertEqual(alice.pk, response.transaction_unsigned.public_key)
                    self.assertEqual(0, response.transaction_unsigned.nonce)

                    self.assertEqual(b'', response.transaction_unsigned.signature)
                    self.assertEqual(b'', response.transaction_unsigned.transaction_hash)

                    self.assertEqual(bob.address, response.transaction_unsigned.transfer.addr_to)
                    self.assertEqual(101, response.transaction_unsigned.transfer.amount)

    def test_transferCoins_push_unsigned(self):
        with set_data_dir('no_data'):
            with State() as db_state:
                with set_wallet_dir("test_wallet"):
                    p2p_factory = Mock(spec=P2PFactory)
                    p2p_factory.pow = Mock(spec=POW)
                    chain_manager = ChainManager(db_state)

                    qrlnode = QRLNode(db_state, slaves=[])
                    qrlnode.set_chain_manager(chain_manager)
                    qrlnode._p2pfactory = p2p_factory
                    qrlnode._pow = p2p_factory.pow
                    qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                    service = PublicAPIService(qrlnode)

                    context = Mock(spec=ServicerContext)

                    alice = get_alice_xmss()
                    bob = get_bob_xmss()

                    request = qrl_pb2.TransferCoinsReq(
                        address_from=alice.address,
                        address_to=bob.address,
                        amount=101,
                        fee=12,
                        xmss_pk=alice.pk
                    )

                    response = service.TransferCoins(request=request, context=context)
                    context.set_code.assert_not_called()
                    context.set_details.assert_not_called()

                    self.assertIsNotNone(response)
                    self.assertIsNotNone(response.transaction_unsigned)
                    self.assertEqual('transfer', response.transaction_unsigned.WhichOneof('transactionType'))

                    self.assertEqual(alice.address, response.transaction_unsigned.addr_from)
                    self.assertEqual(12, response.transaction_unsigned.fee)
                    self.assertEqual(alice.pk, response.transaction_unsigned.public_key)
                    self.assertEqual(0, response.transaction_unsigned.nonce)
                    self.assertEqual(b'', response.transaction_unsigned.signature)
                    self.assertEqual(b'', response.transaction_unsigned.transaction_hash)
                    self.assertEqual(bob.address, response.transaction_unsigned.transfer.addr_to)
                    self.assertEqual(101, response.transaction_unsigned.transfer.amount)

                    req_push = qrl_pb2.PushTransactionReq(transaction_signed=response.transaction_unsigned)

                    resp_push = service.PushTransaction(req_push, context=context)
                    context.set_code.assert_not_called()
                    context.set_details.assert_not_called()

                    self.assertIsNotNone(resp_push)
                    self.assertEqual(qrl_pb2.PushTransactionResp.VALIDATION_FAILED,
                                     resp_push.error_code)

    def test_transferCoins_sign(self):
        with set_data_dir('no_data'):
            with State() as db_state:
                with set_wallet_dir("test_wallet"):
                    p2p_factory = Mock(spec=P2PFactory)
                    p2p_factory.pow = Mock(spec=POW)
                    chain_manager = ChainManager(db_state)

                    qrlnode = QRLNode(db_state, slaves=[])
                    qrlnode.set_chain_manager(chain_manager)
                    qrlnode._p2pfactory = p2p_factory
                    qrlnode._pow = p2p_factory.pow
                    qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                    service = PublicAPIService(qrlnode)

                    context = Mock(spec=ServicerContext)

                    alice = get_alice_xmss()
                    bob = get_bob_xmss()

                    request = qrl_pb2.TransferCoinsReq(
                        address_from=alice.address,
                        address_to=bob.address,
                        amount=101,
                        fee=12,
                        xmss_pk=alice.pk
                    )

                    response = service.TransferCoins(request=request, context=context)
                    context.set_code.assert_not_called()
                    context.set_details.assert_not_called()

                    self.assertIsNotNone(response)
                    self.assertIsNotNone(response.transaction_unsigned)
                    self.assertEqual('transfer', response.transaction_unsigned.WhichOneof('transactionType'))

                    self.assertEqual(alice.address, response.transaction_unsigned.addr_from)
                    self.assertEqual(12, response.transaction_unsigned.fee)
                    self.assertEqual(alice.pk, response.transaction_unsigned.public_key)
                    self.assertEqual(0, response.transaction_unsigned.nonce)
                    self.assertEqual(b'', response.transaction_unsigned.signature)
                    self.assertEqual(b'', response.transaction_unsigned.transaction_hash)
                    self.assertEqual(bob.address, response.transaction_unsigned.transfer.addr_to)
                    self.assertEqual(101, response.transaction_unsigned.transfer.amount)

                    tmp_hash_pre = response.transaction_unsigned.addr_from
                    tmp_hash_pre += str(response.transaction_unsigned.fee).encode()
                    tmp_hash_pre += response.transaction_unsigned.transfer.addr_to
                    tmp_hash_pre += str(response.transaction_unsigned.transfer.amount).encode()

                    self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c939078'
                                     '2a9c61ac02f31320103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb38'
                                     '5ba30f2c1c005a85ebc4419cfd313031',
                                     bin2hstr(tmp_hash_pre))

                    tmp_hash = sha256(tmp_hash_pre)

                    self.assertEqual('3645f2819aba65479f9a7fad3f5d7a41a9357410a595fa02fb947bfe3ed96e0f',
                                     bin2hstr(tmp_hash))

                    signed_transaction = response.transaction_unsigned
                    signed_transaction.signature = alice.sign(tmp_hash)

                    req_push = qrl_pb2.PushTransactionReq(transaction_signed=signed_transaction)

                    resp_push = service.PushTransaction(req_push, context=context)
                    context.set_code.assert_not_called()
                    context.set_details.assert_not_called()

                    self.assertIsNotNone(resp_push)
                    self.assertEqual(qrl_pb2.PushTransactionResp.SUBMITTED,
                                     resp_push.error_code)
                    self.assertEqual('c34d96d036a83378a44a8feb47d01174f8147583a668811451d76a6893aa7045',
                                     bin2hstr(resp_push.tx_hash))
