# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from grpc import ServicerContext
from mock import Mock, patch
from pyqrllib.pyqrllib import bin2hstr, QRLHelper

from qrl.core.ChainManager import ChainManager
from qrl.core.txs.Transaction import Transaction
from qrl.core.State import State
from qrl.core.misc import logger
from qrl.core.node import POW
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_default_balance_size, set_qrl_dir, replacement_getTime

logger.initialize_default()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestPublicAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI, self).__init__(*args, **kwargs)

    @set_default_balance_size()
    def test_messageTxn_sign(self):
        with set_qrl_dir('wallet_ver1'):
            with State() as db_state:
                p2p_factory = Mock(spec=P2PFactory)
                p2p_factory.pow = Mock(spec=POW)
                chain_manager = ChainManager(db_state)

                qrlnode = QRLNode(mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)
                qrlnode._p2pfactory = p2p_factory
                qrlnode._pow = p2p_factory.pow
                qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                service = PublicAPIService(qrlnode)

                context = Mock(spec=ServicerContext)

                alice = get_alice_xmss()
                my_message = b'Hello QRL!'

                request = qrl_pb2.MessageTxnReq(
                    message=my_message,
                    fee=12,
                    xmss_pk=alice.pk
                )

                response = service.GetMessageTxn(request=request, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(response)
                self.assertIsNotNone(response.extended_transaction_unsigned.tx)
                self.assertEqual('message', response.extended_transaction_unsigned.tx.WhichOneof('transactionType'))

                self.assertEqual(12, response.extended_transaction_unsigned.tx.fee)
                self.assertEqual(alice.pk, response.extended_transaction_unsigned.tx.public_key)
                self.assertEqual(0, response.extended_transaction_unsigned.tx.nonce)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.signature)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.transaction_hash)
                self.assertEqual(my_message, response.extended_transaction_unsigned.tx.message.message_hash)

                tmp_hash_pre = response.extended_transaction_unsigned.tx.master_addr
                tmp_hash_pre += response.extended_transaction_unsigned.tx.fee.to_bytes(8, byteorder='big', signed=False)
                tmp_hash_pre += response.extended_transaction_unsigned.tx.message.message_hash

                tmp_hash = sha256(tmp_hash_pre)
                hash_found = bin2hstr(Transaction.from_pbdata(response.extended_transaction_unsigned.tx).
                                      get_data_hash())
                self.assertEqual(hash_found,
                                 bin2hstr(tmp_hash))

                signed_transaction = response.extended_transaction_unsigned.tx
                signed_transaction.signature = alice.sign(tmp_hash)

                req_push = qrl_pb2.PushTransactionReq(transaction_signed=signed_transaction)

                resp_push = service.PushTransaction(req_push, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(resp_push)
                self.assertEqual(qrl_pb2.PushTransactionResp.SUBMITTED,
                                 resp_push.error_code)
                self.assertEqual('b7ee814a548a6bbb8d97b2d3a0eb9e1f8b6ceee49b764e3c7b23d104aca6abeb',
                                 bin2hstr(resp_push.tx_hash))

    @set_default_balance_size()
    def test_transferCoins_get_unsigned(self):
        with set_qrl_dir('wallet_ver1'):
            with State() as db_state:
                p2p_factory = Mock(spec=P2PFactory)
                p2p_factory.pow = Mock(spec=POW)
                chain_manager = ChainManager(db_state)

                qrlnode = QRLNode(mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)
                qrlnode._p2pfactory = p2p_factory
                qrlnode._pow = p2p_factory.pow
                qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                service = PublicAPIService(qrlnode)

                context = Mock(spec=ServicerContext)

                alice = get_alice_xmss()
                bob = get_bob_xmss()

                request = qrl_pb2.TransferCoinsReq(
                    addresses_to=[bob.address],
                    amounts=[101],
                    fee=12,
                    xmss_pk=alice.pk
                )

                response = service.TransferCoins(request=request, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(response)
                self.assertIsNotNone(response.extended_transaction_unsigned)
                self.assertEqual('transfer',
                                 response.extended_transaction_unsigned.tx.WhichOneof('transactionType'))

                self.assertEqual(12, response.extended_transaction_unsigned.tx.fee)
                self.assertEqual(alice.pk, response.extended_transaction_unsigned.tx.public_key)
                self.assertEqual(0, response.extended_transaction_unsigned.tx.nonce)

                self.assertEqual(b'', response.extended_transaction_unsigned.tx.signature)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.transaction_hash)

                self.assertEqual(bob.address, response.extended_transaction_unsigned.tx.transfer.addrs_to[0])
                self.assertEqual(101, response.extended_transaction_unsigned.tx.transfer.amounts[0])

    @set_default_balance_size()
    def test_transferCoins_push_unsigned(self):
        with set_qrl_dir('wallet_ver1'):
            with State() as db_state:
                p2p_factory = Mock(spec=P2PFactory)
                p2p_factory.pow = Mock(spec=POW)
                chain_manager = ChainManager(db_state)

                qrlnode = QRLNode(mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)
                qrlnode._p2pfactory = p2p_factory
                qrlnode._pow = p2p_factory.pow
                qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                service = PublicAPIService(qrlnode)

                context = Mock(spec=ServicerContext)

                alice = get_alice_xmss()
                bob = get_bob_xmss()

                request = qrl_pb2.TransferCoinsReq(
                    addresses_to=[bob.address],
                    amounts=[101],
                    fee=12,
                    xmss_pk=alice.pk
                )

                response = service.TransferCoins(request=request, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(response)
                self.assertIsNotNone(response.extended_transaction_unsigned)
                self.assertEqual('transfer', response.extended_transaction_unsigned.tx.WhichOneof('transactionType'))

                self.assertEqual(12, response.extended_transaction_unsigned.tx.fee)
                self.assertEqual(alice.pk, response.extended_transaction_unsigned.tx.public_key)
                self.assertEqual(0, response.extended_transaction_unsigned.tx.nonce)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.signature)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.transaction_hash)
                self.assertEqual(bob.address, response.extended_transaction_unsigned.tx.transfer.addrs_to[0])
                self.assertEqual(101, response.extended_transaction_unsigned.tx.transfer.amounts[0])

                req_push = qrl_pb2.PushTransactionReq(transaction_signed=response.extended_transaction_unsigned.tx)

                resp_push = service.PushTransaction(req_push, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(resp_push)
                self.assertEqual(qrl_pb2.PushTransactionResp.VALIDATION_FAILED,
                                 resp_push.error_code)

    @set_default_balance_size()
    def test_transferCoins_sign(self):
        with set_qrl_dir('wallet_ver1'):
            with State() as db_state:
                p2p_factory = Mock(spec=P2PFactory)
                p2p_factory.pow = Mock(spec=POW)
                chain_manager = ChainManager(db_state)

                qrlnode = QRLNode(mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)
                qrlnode._p2pfactory = p2p_factory
                qrlnode._pow = p2p_factory.pow
                qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                service = PublicAPIService(qrlnode)

                context = Mock(spec=ServicerContext)

                alice = get_alice_xmss()
                bob = get_bob_xmss()

                request = qrl_pb2.TransferCoinsReq(
                    addresses_to=[bob.address],
                    amounts=[101],
                    fee=12,
                    xmss_pk=alice.pk
                )

                response = service.TransferCoins(request=request, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(response)
                self.assertIsNotNone(response.extended_transaction_unsigned.tx)
                self.assertEqual('transfer', response.extended_transaction_unsigned.tx.WhichOneof('transactionType'))

                self.assertEqual(12, response.extended_transaction_unsigned.tx.fee)
                self.assertEqual(alice.pk, response.extended_transaction_unsigned.tx.public_key)
                self.assertEqual(0, response.extended_transaction_unsigned.tx.nonce)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.signature)
                self.assertEqual(b'', response.extended_transaction_unsigned.tx.transaction_hash)
                self.assertEqual(bob.address, response.extended_transaction_unsigned.tx.transfer.addrs_to[0])
                self.assertEqual(101, response.extended_transaction_unsigned.tx.transfer.amounts[0])

                tmp_hash_pre = bytes(QRLHelper.getAddress(response.extended_transaction_unsigned.tx.public_key))
                tmp_hash_pre += str(response.extended_transaction_unsigned.tx.fee).encode()
                tmp_hash_pre += response.extended_transaction_unsigned.tx.transfer.addrs_to[0]
                tmp_hash_pre += str(response.extended_transaction_unsigned.tx.transfer.amounts[0]).encode()

                self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c939078'
                                 '2a9c61ac02f31320103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb38'
                                 '5ba30f2c1c005a85ebc4419cfd313031',
                                 bin2hstr(tmp_hash_pre))

                tmp_hash = sha256(tmp_hash_pre)

                self.assertEqual('3645f2819aba65479f9a7fad3f5d7a41a9357410a595fa02fb947bfe3ed96e0f',
                                 bin2hstr(tmp_hash))

                signed_transaction = response.extended_transaction_unsigned.tx
                signed_transaction.signature = alice.sign(tmp_hash)

                req_push = qrl_pb2.PushTransactionReq(transaction_signed=signed_transaction)

                resp_push = service.PushTransaction(req_push, context=context)
                context.set_code.assert_not_called()
                context.set_details.assert_not_called()

                self.assertIsNotNone(resp_push)
                self.assertEqual(qrl_pb2.PushTransactionResp.SUBMITTED,
                                 resp_push.error_code)
                self.assertEqual('30955fdc5e2d9dbe5fb9bf812f2e1b6c4b409a8a7c7a75f1c3e9ba1ffdd8e60e',
                                 bin2hstr(resp_push.tx_hash))
