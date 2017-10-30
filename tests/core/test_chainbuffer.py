# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import pytest
from mock import Mock, MagicMock
from timeout_decorator import timeout_decorator

from qrl.core import logger
from qrl.core.ChainBuffer import ChainBuffer
from qrl.core.block import Block
from qrl.core.chain import Chain
from qrl.core.state import State
from qrl.core.wallet import Wallet
from tests.misc.helper import setWalletDir

logger.initialize_default(force_console_output=True)


class TestChainBuffer(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChainBuffer, self).__init__(*args, **kwargs)

    def test_create(self):
        with setWalletDir("test_wallet"):
            # FIXME: cross-dependency
            chain = Mock(spec=Chain)
            chain.height = MagicMock(return_value=0)
            chain.wallet = Wallet()
            cb = ChainBuffer(chain)

            self.assertEqual(0, cb.height())

            tmp_block = cb.get_block(0)
            self.assertIsNone(tmp_block)

            tmp_block = cb.get_last_block()
            self.assertIsNone(tmp_block)

    def test_add_remove(self):
        with setWalletDir("test_wallet"):
            chain = Mock(spec=Chain)
            chain.height = MagicMock(return_value=0)
            chain.wallet = Wallet()
            chain_buffer = ChainBuffer(chain)

            b0 = chain_buffer.get_block(0)
            self.assertIsNone(b0)

            tmp_block = Block()
            chain_buffer.add_pending_block(tmp_block)
