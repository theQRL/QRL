# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

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
    def test_check_chain(self):
        with State() as state:
            self.assertIsNotNone(state)

            chain = Chain(state)
            self.assertIsNotNone(chain)

            self.assertEqual(chain.mining_address,
                             'Q77400de16219522c37e622ce82723eb68e481b07af0b5f0825f95207b3f807027aa9b022')

            self.assertEqual(chain.wallet.address_bundle[0].address,
                             'Q77400de16219522c37e622ce82723eb68e481b07af0b5f0825f95207b3f807027aa9b022')
