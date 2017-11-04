# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, MagicMock

from qrl.core import logger
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Block import Block
from qrl.core.Chain import Chain
from qrl.core.Wallet import Wallet
from tests.misc.helper import setWalletDir

logger.initialize_default(force_console_output=True)


class TestBufferedChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBufferedChain, self).__init__(*args, **kwargs)

    def test_create(self):
        with setWalletDir("test_wallet"):
            # FIXME: cross-dependency
            chain = Mock(spec=Chain)
            chain.height = MagicMock(return_value=0)
            chain.get_block = MagicMock(return_value=None)
            chain.get_last_block = MagicMock(return_value=None)
            chain.wallet = Wallet()
            cb = BufferedChain(chain)

            self.assertEqual(0, cb.height())

            tmp_block = cb.get_block(0)
            self.assertIsNone(tmp_block)
            chain.get_block.assert_called()

            tmp_block = cb.get_last_block()
            self.assertIsNone(tmp_block)

    def test_add_remove(self):
        with setWalletDir("test_wallet"):
            chain = Mock(spec=Chain)
            chain.height = MagicMock(return_value=0)
            chain.get_block = MagicMock(return_value=None)
            chain.wallet = Wallet()
            chain_buffer = BufferedChain(chain)

            b0 = chain_buffer.get_block(0)
            chain_buffer._chain.get_block.assert_called()
            self.assertIsNone(b0)

            tmp_block = Block()
            res = chain_buffer.add_block(tmp_block)


            # tmp_block = Block()
            # res = chain_buffer.add_pending_block(tmp_block)
            # self.assertTrue(res)
            # chain_buffer.process_pending_blocks(0)
