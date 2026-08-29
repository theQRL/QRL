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
keys). Under the default config ots_tracking_per_page == max_ots_tracking_index
== 8192, so those keys occupy a single tracking page and stay below the
ots_counter fallback -- the regime every payment slave actually uses. Heights
>= 14 cross max_ots_tracking_index, where the legacy AddressState path
deliberately falls back to ots_counter and the two representations differ by
design; that is out of scope (and impractical for payment slaves).
"""
from contextlib import suppress
from unittest import TestCase

from mock import Mock, patch

from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.State import State
from qrl.generated import qrl_pb2
from qrl import grpcProxy
from tests.misc.helper import get_alice_xmss, setup_qrl_dir_without_ctx, cleanup_qrl_dir


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
