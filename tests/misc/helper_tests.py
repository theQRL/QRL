# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger

logger.initialize_default()


class TestHelpers(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHelpers, self).__init__(*args, **kwargs)
