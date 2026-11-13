import base64
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

import grpc

from qrl.core import config
from qrl.daemon.walletd import _start_wallet_api
from qrl.generated import qrlwallet_pb2, qrlwallet_pb2_grpc
from qrl.services.wallet_auth import TOKEN_HEADER


class TestWalletAPIStartup(TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        for name, value in (('_qrl_dir', self.directory.name), ('wallet_api_host', '127.0.0.1'),
                            ('wallet_api_port', 0)):
            setting = patch.object(config.user, name, value)
            setting.start()
            self.addCleanup(setting.stop)
        self.walletd = Mock()
        self.walletd.get_wallet_info.return_value = (1, 0, False)
        self.token_path = Path(self.directory.name) / 'wallet_api.token'

    def start_server(self):
        server, port = _start_wallet_api(self.walletd)
        self.addCleanup(lambda: server.stop(0).wait())
        return server, port

    def assert_token_works(self, port, token):
        with grpc.insecure_channel('127.0.0.1:{}'.format(port)) as channel:
            stub = qrlwallet_pb2_grpc.WalletAPIStub(channel)
            response = stub.GetWalletInfo(qrlwallet_pb2.GetWalletInfoReq(),
                                          metadata=((TOKEN_HEADER, token),), timeout=5)
        self.assertEqual(response.version, 1)

    def test_startup_replaces_token_and_enforces_private_permissions(self):
        self.token_path.write_text('old-token')
        os.chmod(self.token_path, 0o644)
        os.chmod(self.directory.name, 0o755)

        _, port = self.start_server()

        self.assertEqual(stat.S_IMODE(os.stat(self.directory.name).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.token_path.stat().st_mode), 0o600)
        token = self.token_path.read_text()
        self.assertNotEqual(token, 'old-token')
        self.assertEqual(len(base64.urlsafe_b64decode(token + '=')), 32)
        self.assert_token_works(port, token)

    def test_restart_invalidates_previous_token(self):
        first_server, first_port = self.start_server()
        first_token = self.token_path.read_text()
        self.assert_token_works(first_port, first_token)
        first_server.stop(0).wait()

        _, second_port = self.start_server()
        second_token = self.token_path.read_text()
        self.assertNotEqual(first_token, second_token)
        self.walletd.reset_mock()
        with grpc.insecure_channel('127.0.0.1:{}'.format(second_port)) as channel:
            stub = qrlwallet_pb2_grpc.WalletAPIStub(channel)
            with self.assertRaises(grpc.RpcError) as caught:
                stub.GetWalletInfo(qrlwallet_pb2.GetWalletInfoReq(),
                                   metadata=((TOKEN_HEADER, first_token),), timeout=5)
            self.assertEqual(caught.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
        self.walletd.get_wallet_info.assert_not_called()
        self.assert_token_works(second_port, second_token)

    def test_non_loopback_hosts_rejected_before_binding_or_token_replacement(self):
        self.token_path.write_text('existing-token')
        for host in ('0.0.0.0', '::', '[::]', '192.0.2.1', 'wallet.example', '', 'localhost.example'):
            with self.subTest(host=host), patch.object(config.user, 'wallet_api_host', host), \
                    patch('qrl.daemon.walletd.grpc.server') as server_factory:
                with self.assertRaisesRegex(ValueError, 'loopback'):
                    _start_wallet_api(self.walletd)
                server_factory.assert_not_called()
                self.assertEqual(self.token_path.read_text(), 'existing-token')

    def test_loopback_binding_uses_numeric_address(self):
        for host, expected in (('localhost', '127.0.0.1:0'), ('127.0.0.2', '127.0.0.2:0'),
                               ('::1', '[::1]:0'), ('[::1]', '[::1]:0')):
            with self.subTest(host=host), patch.object(config.user, 'wallet_api_host', host), \
                    patch('qrl.daemon.walletd.grpc.server') as server_factory:
                server_factory.return_value.add_insecure_port.return_value = 19010
                _start_wallet_api(self.walletd)
                server_factory.return_value.add_insecure_port.assert_called_once_with(expected)

    def test_token_write_failure_prevents_server_start(self):
        with patch('qrl.daemon.walletd.grpc.server') as server_factory, \
                patch('qrl.daemon.walletd.write_private_file', side_effect=OSError('test write failure')):
            server_factory.return_value.add_insecure_port.return_value = 19010
            with self.assertRaises(OSError):
                _start_wallet_api(self.walletd)
            server_factory.return_value.start.assert_not_called()
            server_factory.return_value.stop.assert_called_once_with(0)
