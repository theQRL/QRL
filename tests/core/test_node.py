# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, MagicMock

from qrl.core import logger
from qrl.core.ESyncState import ESyncState
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.node import POS

logger.initialize_default(force_console_output=True)


class TestNode(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestNode, self).__init__(*args, **kwargs)

    def test_create(self):
        buffered_chain = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POS(buffered_chain=buffered_chain,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)

    def test_sync_state_change_unsynced(self):
        buffered_chain = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POS(buffered_chain=buffered_chain,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.unsynced)
        # FIXME: Add more asserts

    def test_sync_state_change_syncing(self):
        buffered_chain = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POS(buffered_chain=buffered_chain,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.syncing)
        # FIXME: Add more asserts

    def test_sync_state_change_synced(self):
        buffered_chain = Mock()
        buffered_chain.height = 0
        buffered_chain.get_block = MagicMock(return_value=GenesisBlock())

        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POS(buffered_chain=buffered_chain,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.synced)
        # FIXME: Add more asserts

    def test_sync_state_change_forked(self):
        buffered_chain = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POS(buffered_chain=buffered_chain,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.forked)
        # FIXME: Add more asserts
