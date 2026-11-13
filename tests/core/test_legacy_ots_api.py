import hashlib
import threading
import tracemalloc
from contextlib import suppress
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from qrl.core import config
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.State import State
from qrl.core.qrlnode import QRLNode
from tests.misc.helper import setup_qrl_dir_without_ctx, cleanup_qrl_dir


def address_for_height(height, body=b'\x00' * 32):
    """
    A well-formed 39-byte address whose descriptor claims the given height.
    No XMSS tree of that height is needed: address validity is consensus-locked
    to the checksum and format nibble, so this is the request from theQRL/QRL#1820.
    """
    payload = bytes([0x01, height // 2, 0x00]) + body
    return payload + hashlib.sha256(payload).digest()[-4:]


class TestLegacyOTSAPI(TestCase):
    def make_chain_manager(self, height, last_page=0):
        manager = object.__new__(ChainManager)
        manager.lock = threading.RLock()
        address = address_for_height(height)
        state = OptimizedAddressState.get_default(address)
        manager.get_optimized_address_state = Mock(return_value=state)
        manager.get_last_bitfield_page = Mock(return_value=last_page)
        manager.get_bitfield = Mock(return_value=[b'\x00'] * config.dev.ots_bitfield_size)
        return manager, address

    def test_height_30_bitfield_is_sized_from_stored_pages(self):
        manager, address = self.make_chain_manager(30)
        self.assertTrue(OptimizedAddressState.address_is_valid(address))

        state = manager.get_address_state(address, exclude_transaction_hashes=True)

        self.assertEqual(len(state.ots_bitfield), config.dev.ots_bitfield_size)
        manager.get_bitfield.assert_called_once_with(address, 1)
        self.assertEqual(state.get_unused_ots_index(0), 0)

    def test_stored_pages_over_limit_rejected_before_reading_pages(self):
        max_pages = config.dev.max_legacy_ots_bitfield_bytes // config.dev.ots_bitfield_size
        manager, address = self.make_chain_manager(30, last_page=max_pages + 1)

        with self.assertRaisesRegex(ValueError, 'legacy API limit'):
            manager.get_address_state(address, exclude_transaction_hashes=True)
        manager.get_bitfield.assert_not_called()

        state = manager.get_address_state(address, exclude_ots_bitfield=True,
                                          exclude_transaction_hashes=True)
        self.assertEqual(len(state.ots_bitfield), 0)

    def test_last_page_is_clamped_to_descriptor_height(self):
        manager, address = self.make_chain_manager(10, last_page=5)
        state = manager.get_address_state(address, exclude_transaction_hashes=True)
        self.assertEqual(len(state.ots_bitfield), config.dev.ots_bitfield_size)
        manager.get_bitfield.assert_called_once_with(address, 1)

    def test_legacy_page_two_starts_at_byte_1024(self):
        manager, address = self.make_chain_manager(14, last_page=2)
        page_one = [b'\xff'] * config.dev.ots_bitfield_size
        page_two = [b'\x01'] + [b'\x00'] * (config.dev.ots_bitfield_size - 1)
        manager.get_bitfield.side_effect = [page_one, page_two]

        state = manager.get_address_state(address, exclude_transaction_hashes=True)
        self.assertEqual(len(state.ots_bitfield), 2048)
        self.assertEqual(state.ots_bitfield[1024], b'\x01')
        self.assertEqual(state.get_unused_ots_index(0), 8193)

        manager.get_bitfield.side_effect = [[b'\xff'] * config.dev.ots_bitfield_size] * 2
        full_state = manager.get_address_state(address, exclude_transaction_hashes=True)
        self.assertIsNone(full_state.get_unused_ots_index(0))

    def test_indexes_past_omitted_pages_are_unused(self):
        manager, address = self.make_chain_manager(30, last_page=3)
        manager.get_bitfield.return_value = [b'\xff'] * config.dev.ots_bitfield_size

        state = manager.get_address_state(address, exclude_transaction_hashes=True)

        self.assertEqual(len(state.ots_bitfield), 3 * config.dev.ots_bitfield_size)
        self.assertEqual(state.get_unused_ots_index(0), 3 * config.dev.ots_tracking_per_page)
        self.assertEqual(state.get_unused_ots_index(10 ** 6), 10 ** 6)
        self.assertIsNone(state.get_unused_ots_index(2 ** 30))

    @patch.object(OptimizedAddressState, 'address_is_valid', return_value=True)
    def test_get_ots_bounds_page_count_and_scan(self, address_is_valid):
        node = object.__new__(QRLNode)
        node._chain_manager = Mock()
        address = address_for_height(30)

        with self.assertRaisesRegex(ValueError, 'page count'):
            node.get_ots(address, 1, config.dev.max_get_ots_pages + 1, 0)
        node._chain_manager.get_bitfield.assert_not_called()

        node._chain_manager.get_bitfield.return_value = [b'\x00'] * config.dev.ots_bitfield_size
        node._chain_manager.get_unused_ots_index2.return_value = 42
        pages, unused, found = node.get_ots(address, 1, 1, 0)
        self.assertEqual(len(pages), 1)
        self.assertEqual((unused, found), (42, True))
        node._chain_manager.get_unused_ots_index2.assert_called_once_with(
            address, 0, max_scan_keys=config.dev.max_get_ots_scan_keys)

    def test_get_ots_scan_limit_is_an_error_not_false_exhaustion(self):
        manager, address = self.make_chain_manager(30)
        paginated = Mock()
        paginated.generate_bitfield_key.return_value = b'page'
        paginated.get_paginated_data.return_value = [b'\xff'] * config.dev.ots_bitfield_size

        with self.assertRaisesRegex(ValueError, 'retry from index 16'):
            manager.get_unused_ots_index({}, {}, address, paginated, max_scan_keys=16)

        paginated.get_paginated_data.return_value = [b'\x07'] + [b'\x00'] * (config.dev.ots_bitfield_size - 1)
        self.assertEqual(manager.get_unused_ots_index({}, {}, address, paginated, max_scan_keys=16), 3)

    def test_legacy_bitfield_is_built_under_one_lock(self):
        manager, address = self.make_chain_manager(14, last_page=2)
        held = []
        manager.lock = MagicMock()
        manager.lock.__enter__ = Mock(side_effect=lambda *a: held.append(True))
        manager.lock.__exit__ = Mock(side_effect=lambda *a: held.append(False))

        def page(*_):
            self.assertEqual(held, [True])
            return [b'\x00'] * config.dev.ots_bitfield_size
        manager.get_last_bitfield_page.side_effect = lambda *_: page() and 2
        manager.get_bitfield.side_effect = page

        manager.get_legacy_ots_bitfield(address, 14)
        self.assertEqual(held, [True, False])

    def test_legacy_set_and_unset_follow_the_tracked_range(self):
        manager, address = self.make_chain_manager(14, last_page=2)
        state = manager.get_address_state(address, exclude_transaction_hashes=True)
        index = config.dev.ots_tracking_per_page + 3

        state.set_ots_key(index)
        self.assertEqual(state.ots_counter, 0)
        self.assertTrue(state.ots_key_reuse(index))
        self.assertFalse(state.ots_key_reuse(index + 1))

        state.unset_ots_key(index, chain_manager=None)
        self.assertFalse(state.ots_key_reuse(index))


class TestHeight30RegressionWithState(TestCase):
    """QRL-3-5 / theQRL/QRL#1820 against a real state DB."""

    def setUp(self):
        self.dst_dir, self.prev_val = setup_qrl_dir_without_ctx('no_data')
        self.state = State()
        with suppress(AttributeError):
            del GenesisBlock.instance
        GenesisBlock()
        self.chain_manager = ChainManager(self.state)
        self.address = address_for_height(30)

    def tearDown(self):
        cleanup_qrl_dir(self.dst_dir, self.prev_val)

    def _mark_used(self, address, used_indices):
        addresses_state = {address: OptimizedAddressState.get_default(address)}
        paginated_bitfield = PaginatedBitfield(True, self.state._db)
        for i in used_indices:
            paginated_bitfield.set_ots_key(addresses_state, address, i)
        paginated_bitfield.put_addresses_bitfield(None)
        OptimizedAddressState.put_optimized_addresses_state(self.state, addresses_state)

    def test_last_stored_page_ignores_other_addresses(self):
        other = address_for_height(30, body=b'\x01' * 32)
        self._mark_used(other, [5 * config.dev.ots_tracking_per_page])
        self.assertEqual(self.chain_manager.get_last_bitfield_page(self.address), 0)

        self._mark_used(self.address, [0, 2 * config.dev.ots_tracking_per_page + 1])
        self.assertEqual(self.chain_manager.get_last_bitfield_page(self.address), 3)
        self.assertEqual(self.chain_manager.get_last_bitfield_page(other), 6)

    def test_get_address_state_allocation_is_bounded(self):
        tracemalloc.start()
        try:
            state = self.chain_manager.get_address_state(self.address)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        # Before the fix this allocated a list of 2**27 entries (~1 GiB).
        self.assertLess(peak, 2 * 1024 * 1024)
        self.assertEqual(len(state.ots_bitfield), config.dev.ots_bitfield_size)
        self.assertEqual(state.get_unused_ots_index(0), 0)

    def test_get_address_state_reflects_sparse_pages(self):
        used = [0, 1, 2 * config.dev.ots_tracking_per_page + 9]
        self._mark_used(self.address, used)

        state = self.chain_manager.get_address_state(self.address)

        self.assertEqual(len(state.ots_bitfield), 3 * config.dev.ots_bitfield_size)
        for index in used:
            self.assertTrue(state.ots_key_reuse(index))
        self.assertEqual(state.get_unused_ots_index(0), 2)
        self.assertEqual(state.get_unused_ots_index(2 * config.dev.ots_tracking_per_page + 9),
                         2 * config.dev.ots_tracking_per_page + 10)
        self.assertEqual(state.get_unused_ots_index(3 * config.dev.ots_tracking_per_page + 5),
                         3 * config.dev.ots_tracking_per_page + 5)

    def test_get_ots_page_reads_are_bounded(self):
        node = object.__new__(QRLNode)
        node._chain_manager = self.chain_manager

        with patch.object(self.chain_manager, 'get_bitfield',
                          wraps=self.chain_manager.get_bitfield) as get_bitfield:
            with self.assertRaisesRegex(ValueError, 'page count'):
                node.get_ots(self.address, 1, 2 ** 30, 0)
            get_bitfield.assert_not_called()

            pages, unused, found = node.get_ots(self.address, 1, config.dev.max_get_ots_pages, 0)

        self.assertEqual(len(pages), config.dev.max_get_ots_pages)
        self.assertEqual(get_bitfield.call_count, config.dev.max_get_ots_pages)
        self.assertEqual((unused, found), (0, True))
