# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger

logger.initialize_default(force_console_output=True)


# FIXME: These tests will soon be removed
class TestP2PProtocol(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestP2PProtocol, self).__init__(*args, **kwargs)
