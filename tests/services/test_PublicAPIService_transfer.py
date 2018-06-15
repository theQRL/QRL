# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from grpc import ServicerContext
from mock import Mock, patch
from pyqrllib.pyqrllib import bin2hstr, QRLHelper

from qrl.core.ChainManager import ChainManager
from qrl.core.txs.TransferTransaction import TransferTransaction
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
    def test_transferCoins_push_unsigned(self):
        with set_qrl_dir('wallet_ver1'):
            with State() as db_state:
                p2p_factory = Mock(spec=P2PFactory)
                p2p_factory.pow = Mock(spec=POW)
                chain_manager = ChainManager(db_state)

                qrlnode = QRLNode(db_state, mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)
                qrlnode._p2pfactory = p2p_factory
                qrlnode._pow = p2p_factory.pow
                qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                service = PublicAPIService(qrlnode)

                context = Mock(spec=ServicerContext)

                alice = get_alice_xmss()
                bob = get_bob_xmss()

                tx = TransferTransaction.create(addrs_to=[bob.address],
                                                amounts=[101],
                                                fee=12,
                                                xmss_pk=alice.pk)
                tx = tx.pbdata

                self.assertEqual('transfer', tx.WhichOneof('transactionType'))

                self.assertEqual(12, tx.fee)
                self.assertEqual(alice.pk, tx.public_key)
                self.assertEqual(0, tx.nonce)
                self.assertEqual(b'', tx.signature)
                self.assertEqual(b'', tx.transaction_hash)
                self.assertEqual(bob.address, tx.transfer.addrs_to[0])
                self.assertEqual(101, tx.transfer.amounts[0])

                req_push = qrl_pb2.PushTransactionReq(transaction_signed=tx)

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

                qrlnode = QRLNode(db_state, mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)
                qrlnode._p2pfactory = p2p_factory
                qrlnode._pow = p2p_factory.pow
                qrlnode._peer_addresses = ['127.0.0.1', '192.168.1.1']

                service = PublicAPIService(qrlnode)

                context = Mock(spec=ServicerContext)

                alice = get_alice_xmss()
                bob = get_bob_xmss()

                tx = TransferTransaction.create(addrs_to=[bob.address],
                                                amounts=[101],
                                                fee=12,
                                                xmss_pk=alice.pk)
                tx = tx.pbdata
                self.assertEqual('transfer', tx.WhichOneof('transactionType'))

                self.assertEqual(12, tx.fee)
                self.assertEqual(alice.pk, tx.public_key)
                self.assertEqual(0, tx.nonce)
                self.assertEqual(b'', tx.signature)
                self.assertEqual(b'', tx.transaction_hash)
                self.assertEqual(bob.address, tx.transfer.addrs_to[0])
                self.assertEqual(101, tx.transfer.amounts[0])

                tmp_hash_pre = bytes(QRLHelper.getAddress(tx.public_key))
                tmp_hash_pre += str(tx.fee).encode()
                tmp_hash_pre += tx.transfer.addrs_to[0]
                tmp_hash_pre += str(tx.transfer.amounts[0]).encode()

                self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c939078'
                                 '2a9c61ac02f31320103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb38'
                                 '5ba30f2c1c005a85ebc4419cfd313031',
                                 bin2hstr(tmp_hash_pre))

                tmp_hash = sha256(tmp_hash_pre)

                self.assertEqual('3645f2819aba65479f9a7fad3f5d7a41a9357410a595fa02fb947bfe3ed96e0f',
                                 bin2hstr(tmp_hash))

                signed_transaction = tx
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
