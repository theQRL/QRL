# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from unittest import TestCase
from unittest.mock import Mock, patch

import grpc

from qrl.core import config
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.State import State
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2, qrl_pb2_grpc
from qrl.services.PublicAPIService import PublicAPIService
from qrl.services.grpcHelper import request_unused_ots_index
from tests.core.test_legacy_ots_api import address_for_height
from tests.misc.helper import setup_qrl_dir_without_ctx, cleanup_qrl_dir


class FakeRpcError(grpc.RpcError):
    def __init__(self, code, details):
        self._code = code
        self._details = details

    def code(self):
        return self._code

    def details(self):
        return self._details


def retry_error(index):
    return FakeRpcError(grpc.StatusCode.INVALID_ARGUMENT,
                        'OTS scan limit reached; retry from index {}'.format(index))


class TestRequestUnusedOTSIndex(TestCase):
    def test_follows_retry_index_until_found(self):
        stub = Mock()
        stub.GetOTS.side_effect = [retry_error(16), retry_error(32),
                                   Mock(unused_ots_index_found=True, next_unused_ots_index=40)]

        self.assertEqual(request_unused_ots_index(stub, b'addr', 0), 40)
        starts = [c[1]['request'].unused_ots_index_from for c in stub.GetOTS.call_args_list]
        self.assertEqual(starts, [0, 16, 32])

    def test_none_only_when_node_reports_no_key(self):
        stub = Mock()
        stub.GetOTS.side_effect = [retry_error(16), Mock(unused_ots_index_found=False)]
        self.assertIsNone(request_unused_ots_index(stub, b'addr', 0))

    def test_other_errors_propagate(self):
        stub = Mock()
        stub.GetOTS.side_effect = FakeRpcError(grpc.StatusCode.INVALID_ARGUMENT,
                                               'GetOTS page count exceeds limit of 32')
        with self.assertRaises(grpc.RpcError):
            request_unused_ots_index(stub, b'addr', 0)

        stub.GetOTS.side_effect = FakeRpcError(grpc.StatusCode.UNAVAILABLE,
                                               'OTS scan limit reached; retry from index 16')
        with self.assertRaises(grpc.RpcError):
            request_unused_ots_index(stub, b'addr', 0)

    def test_retry_index_must_advance(self):
        stub = Mock()
        stub.GetOTS.side_effect = [retry_error(16), retry_error(16)]
        with self.assertRaises(grpc.RpcError):
            request_unused_ots_index(stub, b'addr', 0)
        self.assertEqual(stub.GetOTS.call_count, 2)

    def test_rejects_index_below_start(self):
        stub = Mock()
        stub.GetOTS.return_value = Mock(unused_ots_index_found=True, next_unused_ots_index=3)
        with self.assertRaisesRegex(ValueError, 'below the requested start'):
            request_unused_ots_index(stub, b'addr', 5)


class TestRequestUnusedOTSIndexOverGrpc(TestCase):
    """The retry index survives GrpcExceptionWrapper and the wire."""

    def setUp(self):
        self.dst_dir, self.prev_val = setup_qrl_dir_without_ctx('no_data')
        self.state = State()
        with suppress(AttributeError):
            del GenesisBlock.instance
        GenesisBlock()
        self.chain_manager = ChainManager(self.state)
        node = object.__new__(QRLNode)
        node._chain_manager = self.chain_manager

        self.executor = ThreadPoolExecutor(max_workers=1)
        self.server = grpc.server(self.executor)
        qrl_pb2_grpc.add_PublicAPIServicer_to_server(PublicAPIService(node), self.server)
        port = self.server.add_insecure_port('127.0.0.1:0')
        self.server.start()
        self.channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        self.stub = qrl_pb2_grpc.PublicAPIStub(self.channel)

    def tearDown(self):
        self.channel.close()
        self.server.stop(0).wait()
        self.executor.shutdown(wait=True)  # --threadleak in CI's test_leaks_other job
        cleanup_qrl_dir(self.dst_dir, self.prev_val)

    def test_scan_limit_is_resumed_not_reported_as_exhausted(self):
        address = address_for_height(18)
        addresses_state = {address: OptimizedAddressState.get_default(address)}
        paginated_bitfield = PaginatedBitfield(True, self.state._db)
        for i in range(40):
            paginated_bitfield.set_ots_key(addresses_state, address, i)
        paginated_bitfield.put_addresses_bitfield(None)
        OptimizedAddressState.put_optimized_addresses_state(self.state, addresses_state)

        with patch.object(config.dev, 'max_get_ots_scan_keys', 16):
            with self.assertRaises(grpc.RpcError) as raw:
                self.stub.GetOTS(request=qrl_pb2.GetOTSReq(address=address))
            self.assertEqual(raw.exception.code(), grpc.StatusCode.INVALID_ARGUMENT)
            self.assertIn('retry from index 16', raw.exception.details())

            self.assertEqual(request_unused_ots_index(self.stub, address, 0), 40)
