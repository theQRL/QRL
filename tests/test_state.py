# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrlcore import logger
from qrlcore.state import State

logger.initialize_default(force_console_output=True)


class TestState(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestState, self).__init__(*args, **kwargs)

    def test_create_state(self):
        state = State()
        self.assertIsNotNone(state)  # to avoid warning (unused variable)

    def test_setget_peers(self):
        state = State()

        tmp_peers = ['A', 'B', 'C']
        state.state_put_peers(tmp_peers)

        peers = state.state_get_peers()
        self.assertEqual(tmp_peers, peers)

    def test_get_peers_empty(self):
        state = State()

        peers = state.state_get_peers()
        self.assertEqual([], peers)
