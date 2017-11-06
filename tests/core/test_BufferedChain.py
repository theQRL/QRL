# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from unittest import TestCase

from mock import Mock, MagicMock
from pyqrllib.pyqrllib import Xmss

from qrl.core import logger
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Block import Block
from qrl.core.Chain import Chain
from qrl.core.State import State
from qrl.core.Transaction import CoinBase, StakeTransaction
from qrl.core.Wallet import Wallet
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
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

            self.assertEqual(0, cb.height)

            tmp_block = cb.get_block(0)
            self.assertIsNone(tmp_block)
            chain.get_block.assert_called()

            tmp_block = cb.get_last_block()
            self.assertIsNone(tmp_block)

    def test_add_empty(self):
        with State() as state:
            with setWalletDir("test_wallet"):
                chain = Mock(spec=Chain)
                chain.height = MagicMock(return_value=0)
                chain.get_block = MagicMock(return_value=None)
                chain.wallet = Wallet()
                chain.pstate = state

                buffered_chain = BufferedChain(chain)

                b0 = buffered_chain.get_block(0)
                buffered_chain._chain.get_block.assert_called()
                self.assertIsNone(b0)

                tmp_block = Block()
                res = buffered_chain.add_block_internal(block=tmp_block)
                self.assertFalse(res)

    def test_add_remove(self):
        with State() as state:
            with setWalletDir("test_wallet"):
                chain = Mock(spec=Chain)
                chain.height = MagicMock(return_value=0)
                chain.get_block = MagicMock(return_value=None)
                chain.wallet = Wallet()
                chain.pstate = state

                buffered_chain = BufferedChain(chain)

                b0 = buffered_chain.get_block(0)
                buffered_chain._chain.get_block.assert_called()
                self.assertIsNone(b0)

                xmss_height = 4
                seed = bytes([i for i in range(48)])
                xmss = XMSS(xmss_height + 2, seed)
                slave_xmss = XMSS(xmss_height, seed)

                h0 = sha256(b'hashchain_seed')
                h1 = sha256(h0)

                stake_transaction = StakeTransaction.create(activation_blocknumber=0,
                                                            blocknumber_headerhash=dict(),
                                                            xmss=xmss,
                                                            slavePK=slave_xmss.pk(),
                                                            hashchain_terminator=h1)

                chain.pstate.stake_validators_list.add_sv(balance=100,
                                                          stake_txn=stake_transaction,
                                                          blocknumber=0)

                tmp_block = Block.create(staking_address=bytes(xmss.get_address().encode()),
                                         block_number=1,
                                         reveal_hash=h0,
                                         prevblock_headerhash=sha256(b'prev_block'),
                                         transactions=[stake_transaction],
                                         duplicate_transactions=OrderedDict(),
                                         signing_xmss=xmss,
                                         nonce=1)

                res = buffered_chain.add_block(block=tmp_block)
                self.assertFalse(res)
