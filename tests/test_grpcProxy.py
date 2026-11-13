# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
"""Safety guard for the grpcProxy migration from GetAddressState to GetOTS/IsSlave.

grpcProxy.set_unused_ots_key now asks the node for the next unused OTS index via
GetOTS -> qrlnode.get_ots -> ChainManager.get_unused_ots_index2, instead of
pulling the whole (unpaginated) AddressState and scanning the bitfield with
AddressState.ots_key_reuse client-side.

Choosing a *used* OTS index would mean XMSS one-time-signature key reuse, so the
core test here pins the safety property: for the same on-disk bitfield state, the
new paginated path must return exactly the same index the old client-side scan
would have.

Scope: equivalence is asserted for real XMSS heights (even, <= 12 -> <= 4096
keys). The legacy AddressState rebuild used to drop bitfield pages above 8192
keys. Walletd now asks GetOTS directly for slave indices, so it does not depend
on that reconstructed bitfield.
"""
from contextlib import suppress
import os
import tempfile
from unittest import TestCase

import simplejson as json
from mock import Mock, patch
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.State import State
from qrl.generated import qrl_pb2
from qrl import grpcProxy
from tests.misc.helper import get_alice_xmss, get_slave_xmss, setup_qrl_dir_without_ctx, cleanup_qrl_dir


class TestGetUnusedOTSIndexEquivalence(TestCase):
    """The new GetOTS-based index selection must match the old client-side scan."""

    def setUp(self):
        self.dst_dir, self.prev_val = setup_qrl_dir_without_ctx('no_data')
        self.state = State()
        with suppress(AttributeError):
            del GenesisBlock.instance  # reset the singleton for this test's qrl_dir
        GenesisBlock()
        self.chain_manager = ChainManager(self.state)

    def tearDown(self):
        cleanup_qrl_dir(self.dst_dir, self.prev_val)

    def _mark_used(self, address, used_indices):
        addresses_state = {address: OptimizedAddressState.get_default(address)}
        paginated_bitfield = PaginatedBitfield(True, self.state._db)
        for i in used_indices:
            paginated_bitfield.set_ots_key(addresses_state, address, i)
        paginated_bitfield.put_addresses_bitfield(None)
        OptimizedAddressState.put_optimized_addresses_state(self.state, addresses_state)

    @staticmethod
    def _legacy_first_unused(addr_state, height, start):
        # Exactly what the removed grpcProxy.set_unused_ots_key scan did.
        for i in range(start, 2 ** height):
            if not addr_state.ots_key_reuse(i):
                return i
        return None

    def _assert_equivalent(self, address, height, starts):
        # Reconstruct the legacy AddressState once (this is what GetAddressState
        # returned to the old proxy); the state does not change between starts.
        addr_state = self.chain_manager.get_address_state(address)
        for start in starts:
            expected = self._legacy_first_unused(addr_state, height, start)
            found = self.chain_manager.get_unused_ots_index2(address, start)
            self.assertEqual(expected, found,
                             "index mismatch at start={} (height={})".format(start, height))

    def test_no_keys_used(self):
        xmss = get_alice_xmss(6)  # 64 keys
        self._assert_equivalent(xmss.address, xmss.height, range(0, 2 ** xmss.height + 1))

    def test_scattered_keys_used(self):
        xmss = get_alice_xmss(6)
        self._mark_used(xmss.address, [0, 1, 2, 5, 8, 9, 16, 31, 32, 33, 62, 63])
        self._assert_equivalent(xmss.address, xmss.height, range(0, 2 ** xmss.height + 1))

    def test_all_keys_used(self):
        xmss = get_alice_xmss(6)
        self._mark_used(xmss.address, range(0, 2 ** xmss.height))
        self._assert_equivalent(xmss.address, xmss.height, range(0, 2 ** xmss.height + 1))
        # No unused index anywhere -> both paths return None.
        self.assertIsNone(self.chain_manager.get_unused_ots_index2(xmss.address, 0))

    def test_larger_height_sampled(self):
        xmss = get_alice_xmss(10)  # 1024 keys, still a single tracking page
        used = [0, 1, 7, 8, 63, 64, 255, 256, 511, 512, 1022, 1023]
        self._mark_used(xmss.address, used)
        starts = [0, 1, 2, 7, 8, 9, 63, 64, 255, 256, 511, 512, 1021, 1022, 1023, 1024]
        self._assert_equivalent(xmss.address, xmss.height, starts)


class TestGrpcProxyPaymentHelpers(TestCase):
    """Direct coverage of the changed grpcProxy helpers using a mocked stub."""

    def test_set_unused_ots_key_sets_index_from_getots(self):
        stub = Mock()
        stub.GetOTS.return_value = Mock(unused_ots_index_found=True, next_unused_ots_index=7)
        xmss = get_alice_xmss(6)

        result = grpcProxy.set_unused_ots_key(stub, xmss, start=3)

        self.assertTrue(result)
        self.assertEqual(7, xmss.ots_index)
        request = stub.GetOTS.call_args[1]['request']
        self.assertEqual(xmss.address, request.address)
        self.assertEqual(3, request.unused_ots_index_from)
        self.assertEqual(0, request.page_count)  # no bitfield pages requested

    def test_set_unused_ots_key_returns_false_when_none_found(self):
        stub = Mock()
        stub.GetOTS.return_value = Mock(unused_ots_index_found=False, next_unused_ots_index=0)
        xmss = get_alice_xmss(6)
        xmss.set_ots_index(5)

        result = grpcProxy.set_unused_ots_key(stub, xmss, start=3)

        self.assertFalse(result)
        self.assertEqual(5, xmss.ots_index)  # unchanged

    def test_set_unused_ots_key_rejects_index_below_requested_floor(self):
        stub = Mock()
        stub.GetOTS.return_value = Mock(unused_ots_index_found=True, next_unused_ots_index=0)
        xmss = get_alice_xmss(6)

        with self.assertRaises(ValueError):
            grpcProxy.set_unused_ots_key(stub, xmss, start=1)
        self.assertEqual(0, xmss.ots_index)

    def test_valid_payment_permission_true_for_registered_slave(self):
        stub = Mock()
        stub.IsSlave.return_value = Mock(result=True)
        xmss = get_alice_xmss(6)

        result = grpcProxy.valid_payment_permission(stub, b'master_address', xmss, '{}')

        self.assertTrue(result)
        stub.PushTransaction.assert_not_called()
        request = stub.IsSlave.call_args[1]['request']
        self.assertEqual(b'master_address', request.master_address)
        self.assertEqual(xmss.pk, request.slave_pk)

    def test_valid_payment_permission_pushes_registration_when_not_slave(self):
        stub = Mock()
        stub.IsSlave.return_value = Mock(result=False)
        xmss = get_alice_xmss(6)

        fake_tx = Mock()
        fake_tx.pbdata = qrl_pb2.Transaction()  # real message so PushTransactionReq accepts it
        with patch('qrl.grpcProxy.Transaction.from_json', return_value=fake_tx) as from_json:
            result = grpcProxy.valid_payment_permission(stub, b'master_address', xmss, '{"slave": "txn"}')

        self.assertIsNone(result)
        from_json.assert_called_once_with('{"slave": "txn"}')
        stub.PushTransaction.assert_called_once()


class TestGrpcProxyPaymentOTSPersistence(TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.qrl_dir = patch.object(grpcProxy.config.user, '_qrl_dir', self.directory.name)
        self.qrl_dir.start()
        self.addCleanup(self.qrl_dir.stop)
        self.slave = get_alice_xmss(6)
        self.address = bin2hstr(self.slave.address)
        self.path = os.path.join(self.directory.name, 'payment_slaves.json')
        with open(self.path, 'w') as outfile:
            json.dump([self.address, [list(self.slave.extended_seed)], '{}'], outfile)
        self.slaves = patch.object(grpcProxy, 'payment_slaves', grpcProxy.read_slaves(self.path), create=True)
        self.slaves.start()
        self.addCleanup(self.slaves.stop)
        self.payment_xmss = patch.object(grpcProxy, 'payment_xmss', None, create=True)
        self.payment_xmss.start()
        self.addCleanup(self.payment_xmss.stop)
        self.stub = Mock()
        self.stub.IsSlave.return_value = Mock(result=True)
        self.stub.GetOTS.side_effect = lambda request: Mock(
            unused_ots_index_found=True,
            next_unused_ots_index=request.unused_ots_index_from)
        self.stub.PushTransaction.return_value = Mock(error_code=qrl_pb2.PushTransactionResp.SUBMITTED)

    def _transfer(self):
        with patch.object(grpcProxy, 'get_public_stub', return_value=self.stub):
            return grpcProxy.transfer([{'address': 'Q' + self.address, 'amount': 1}], 1, 0, 0)

    def test_persist_syncs_cwd_for_relative_wallet_path(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.directory.name)
        self.slave.set_ots_index(1)
        with patch.object(type(grpcProxy.config.user), 'mining_pool_payment_wallet_path',
                          new='payment_slaves.json'):
            grpcProxy.persist_payment_ots_index(self.slave)
        with open(self.path) as infile:
            self.assertEqual(json.load(infile)[3], {self.address: 1})

    def test_restart_uses_persisted_floor_when_node_forgets_unmined_payment(self):
        observed = []

        def check_persisted_index(request):
            with open(self.path) as infile:
                observed.append(json.load(infile)[3][self.address])
            return Mock(error_code=qrl_pb2.PushTransactionResp.SUBMITTED)

        self.stub.PushTransaction.side_effect = check_persisted_index
        self._transfer()
        grpcProxy.payment_slaves = grpcProxy.read_slaves(self.path)
        grpcProxy.payment_xmss = None
        self._transfer()

        self.assertEqual([1, 2], observed)
        self.assertEqual([0, 1], [call.kwargs['request'].unused_ots_index_from
                                  for call in self.stub.GetOTS.call_args_list])
        self.assertEqual(0o600, os.stat(self.path).st_mode & 0o777)

    def test_failed_persistence_prevents_broadcast_and_retry_skips_signed_index(self):
        with patch('qrl.grpcProxy.write_private_file', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                self._transfer()
        self.stub.PushTransaction.assert_not_called()

        self._transfer()
        self.assertEqual([0, 1], [call.kwargs['request'].unused_ots_index_from
                                  for call in self.stub.GetOTS.call_args_list])
        with open(self.path) as infile:
            self.assertEqual(2, json.load(infile)[3][self.address])

    def test_rejects_invalid_persisted_index_instead_of_starting_at_zero(self):
        with open(self.path, 'w') as outfile:
            json.dump([self.address, [list(self.slave.extended_seed)], '{}',
                       {self.address: 'not-an-index'}], outfile)
        with self.assertRaises(ValueError):
            grpcProxy.read_slaves(self.path)

    def test_exhausted_slave_rotates_without_losing_its_saved_floor(self):
        next_slave = get_slave_xmss()
        next_address = bin2hstr(next_slave.address)
        with open(self.path, 'w') as outfile:
            json.dump([self.address, [list(self.slave.extended_seed), list(next_slave.extended_seed)],
                       '{}', {self.address: 64}], outfile)
        grpcProxy.payment_slaves = grpcProxy.read_slaves(self.path)
        self.stub.GetOTS.side_effect = lambda request: Mock(
            unused_ots_index_found=request.unused_ots_index_from < 64,
            next_unused_ots_index=request.unused_ots_index_from)

        self._transfer()

        self.assertEqual([64, 0], [call.kwargs['request'].unused_ots_index_from
                                  for call in self.stub.GetOTS.call_args_list])
        with open(self.path) as infile:
            self.assertEqual({self.address: 64, next_address: 1}, json.load(infile)[3])
