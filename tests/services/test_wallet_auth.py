from concurrent.futures import ThreadPoolExecutor
from unittest import TestCase

import grpc
from mock import Mock

from qrl.generated import qrlwallet_pb2, qrlwallet_pb2_grpc
from qrl.services.WalletAPIService import WalletAPIService
from qrl.services.wallet_auth import WalletAuthInterceptor, TOKEN_HEADER


class TestWalletAuth(TestCase):
    def setUp(self):
        self.methods = qrlwallet_pb2.DESCRIPTOR.services_by_name['WalletAPI'].methods
        self.servicer = WalletAPIService(Mock())
        for method in self.methods:
            response_type = getattr(qrlwallet_pb2, method.output_type.name)
            setattr(self.servicer, method.name, Mock(return_value=response_type()))

        self.executor = ThreadPoolExecutor(max_workers=1)
        self.server = grpc.server(self.executor, interceptors=(WalletAuthInterceptor('test-token'),))
        qrlwallet_pb2_grpc.add_WalletAPIServicer_to_server(self.servicer, self.server)
        port = self.server.add_insecure_port('127.0.0.1:0')
        self.server.start()
        self.channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        self.stub = qrlwallet_pb2_grpc.WalletAPIStub(self.channel)

    def tearDown(self):
        self.channel.close()
        self.server.stop(0).wait()
        self.executor.shutdown(wait=True)

    def test_all_wallet_rpcs_require_token(self):
        invalid_metadata = {
            'missing': None,
            'empty': ((TOKEN_HEADER, ''),),
            'wrong': ((TOKEN_HEADER, 'wrong-token'),),
            'wrong_header': (('authorization', 'test-token'),),
            'duplicate_valid': ((TOKEN_HEADER, 'test-token'), (TOKEN_HEADER, 'test-token')),
            'valid_then_wrong': ((TOKEN_HEADER, 'test-token'), (TOKEN_HEADER, 'wrong-token')),
            'wrong_then_valid': ((TOKEN_HEADER, 'wrong-token'), (TOKEN_HEADER, 'test-token')),
        }
        for method in self.methods:
            request = getattr(qrlwallet_pb2, method.input_type.name)()
            rpc = getattr(self.stub, method.name)
            for case, metadata in invalid_metadata.items():
                with self.subTest(method=method.name, case=case):
                    with self.assertRaises(grpc.RpcError) as caught:
                        rpc(request, metadata=metadata, timeout=5)
                    self.assertEqual(caught.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
            getattr(self.servicer, method.name).assert_not_called()

    def test_all_wallet_rpcs_accept_single_valid_token(self):
        for method in self.methods:
            with self.subTest(method=method.name):
                request = getattr(qrlwallet_pb2, method.input_type.name)()
                response = getattr(self.stub, method.name)(
                    request, metadata=((TOKEN_HEADER, 'test-token'),), timeout=5)
                self.assertIsInstance(response, getattr(qrlwallet_pb2, method.output_type.name))
                getattr(self.servicer, method.name).assert_called_once()
