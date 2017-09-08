# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import pytest
from timeout_decorator import timeout_decorator

from qrl.core import logger
from qrl.core.chain import Chain
from qrl.core.state import State

logger.initialize_default(force_console_output=True)


class TestChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChain, self).__init__(*args, **kwargs)
        # test_dir = os.path.dirname(os.path.abspath(__file__))
        # config.user.wallet_path = os.path.join(test_dir, 'known_data/testcase1')

    @timeout_decorator.timeout(60)
    @pytest.mark.skip(reason="no way of currently testing this")
    def test_check_chain(self):
        with State() as state:
            self.assertIsNotNone(state)

            chain = Chain(state)
            self.assertIsNotNone(chain)
            # chain.my

            self.assertEqual(chain.mining_address,
                             'Q5897606f1c347afc1c099b08cd09d72626a6c4b503a3a1207e1b189c0a2bbab618f7')

            self.assertEqual(chain.my[0][0],
                             'Q5897606f1c347afc1c099b08cd09d72626a6c4b503a3a1207e1b189c0a2bbab618f7')

            # TODO: Add more checks for data stability
