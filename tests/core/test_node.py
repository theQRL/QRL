# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, MagicMock
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core.misc import logger
from qrl.core.ESyncState import ESyncState
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.node import POW

logger.initialize_default()


class TestNode(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestNode, self).__init__(*args, **kwargs)

    def test_create(self):
        chain_manager = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POW(chain_manager=chain_manager,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)

    def test_sync_state_change_unsynced(self):
        chain_manager = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POW(chain_manager=chain_manager,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.unsynced)
        # FIXME: Add more asserts

    def test_sync_state_change_syncing(self):
        chain_manager = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POW(chain_manager=chain_manager,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.syncing)
        # FIXME: Add more asserts

    def test_sync_state_change_synced(self):
        chain_manager = Mock()
        chain_manager.height = 0
        chain_manager.get_block = MagicMock(return_value=GenesisBlock())
        chain_manager.last_block = GenesisBlock()
        chain_manager.tx_pool = Mock()
        chain_manager.tx_pool.transaction_pool = []

        get_block_metadata_response = Mock()
        get_block_metadata_response.block_difficulty = StringToUInt256('2')
        chain_manager.state.get_block_metadata = MagicMock(return_value=get_block_metadata_response)

        p2p_factory = Mock()
        sync_state = Mock()

        get_address_response = Mock()
        get_address_response.nonce = 1
        sync_state.get_address = MagicMock(return_value=get_address_response)

        time_provider = Mock()

        node = POW(chain_manager=chain_manager,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.synced)
        # FIXME: Add more asserts

    def test_sync_state_change_forked(self):
        chain_manager = Mock()
        p2p_factory = Mock()
        sync_state = Mock()
        time_provider = Mock()

        node = POW(chain_manager=chain_manager,
                   p2p_factory=p2p_factory,
                   sync_state=sync_state,
                   time_provider=time_provider)

        self.assertIsNotNone(node)
        node.update_node_state(ESyncState.forked)
        # FIXME: Add more asserts
