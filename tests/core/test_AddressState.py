# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from random import shuffle
from unittest import TestCase

from tests.misc.helper import get_random_xmss
from qrl.core.misc import logger
from qrl.core import config
from qrl.core.AddressState import AddressState

logger.initialize_default()


class TestAddressState(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestAddressState, self).__init__(*args, **kwargs)

    def test_ots_key_validation(self):
        random_xmss = get_random_xmss(xmss_height=12)
        addr = AddressState.get_default(random_xmss.address)
        ots_indexes = list(range(0, 2 ** random_xmss.height))
        shuffle(ots_indexes)

        for i in ots_indexes:
            if i < config.dev.max_ots_tracking_index:
                self.assertFalse(addr.ots_key_reuse(i))
            else:
                result = addr.ots_key_reuse(i)
                if i > addr.ots_counter:
                    self.assertFalse(result)
                else:
                    self.assertTrue(result)

            addr.set_ots_key(i)

            self.assertTrue(addr.ots_key_reuse(i))
