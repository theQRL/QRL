# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from unittest import TestCase

from mock import patch

import qrl
from qrl.core import logger
from qrl.core.Block import Block
from qrl.core.Chain import Chain
from qrl.core.State import State
from qrl.core.VoteMetadata import VoteMetadata
from qrl.core.AddressState import AddressState
from tests.misc.helper import set_wallet_dir, get_alice_xmss

logger.initialize_default(force_console_output=True)


class TestChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChain, self).__init__(*args, **kwargs)
        # test_dir = os.path.dirname(os.path.abspath(__file__))
        # config.user.wallet_path = os.path.join(test_dir, 'known_data/testcase1')

    def test_create(self):
        with set_wallet_dir("test_wallet"):
            with State() as state:
                self.assertIsNotNone(state)

                chain = Chain(state)
                self.assertIsNotNone(chain)

                self.assertEqual(chain.staking_address,
                                 b'Q1d6222fe3e53fafe8ce33acd2f8385c6dc044ab55452f0ebceb4d00233935ffaa72dd826')

                self.assertEqual(chain.wallet.address_bundle[0].address,
                                 b'Q1d6222fe3e53fafe8ce33acd2f8385c6dc044ab55452f0ebceb4d00233935ffaa72dd826')

    def test_last_block(self):
        with set_wallet_dir("test_wallet"):
            with State() as state:
                self.assertIsNotNone(state)

                chain = Chain(state)
                alice_xmss = get_alice_xmss()
                staking_address = bytes(alice_xmss.get_address().encode())

                address_state_dict = dict()
                address_state_dict[staking_address] = AddressState.create(address=staking_address,
                                                                          nonce=0,
                                                                          balance=100,
                                                                          pubhashes=[])

                tmp_block1 = Block.create(staking_address=staking_address,
                                          block_number=0,
                                          reveal_hash=bytes(),
                                          prevblock_headerhash=bytes(),
                                          transactions=[],
                                          duplicate_transactions=OrderedDict(),
                                          vote=VoteMetadata(),
                                          signing_xmss=alice_xmss,
                                          nonce=address_state_dict[staking_address].nonce + 1)

                res = chain.add_block(tmp_block1, address_state_dict, None)
                address_state_dict[staking_address].increase_nonce()
                address_state_dict[staking_address].balance += tmp_block1.block_reward
                self.assertTrue(res)
                self.assertEqual(0, chain.height)           # FIXME: wrong name, it is not height but max_index

                last_block = chain.get_last_block()
                self.assertEqual(tmp_block1, last_block)

    def test_add_many_and_save(self):
        with set_wallet_dir("test_wallet"):
            with State() as state:
                self.assertIsNotNone(state)

                chain = Chain(state)
                alice_xmss = get_alice_xmss()
                staking_address = bytes(alice_xmss.get_address().encode())

                with patch('qrl.core.config.dev.disk_writes_after_x_blocks'):
                    qrl.core.config.dev.disk_writes_after_x_blocks = 4

                    prev = bytes()
                    address_state_dict = dict()
                    address_state_dict[staking_address] = AddressState.create(address=staking_address,
                                                                              nonce=0,
                                                                              balance=100,
                                                                              pubhashes=[])
                    for i in range(10):
                        tmp_block1 = Block.create(staking_address=staking_address,
                                                  block_number=i,
                                                  reveal_hash=bytes(),
                                                  prevblock_headerhash=prev,
                                                  transactions=[],
                                                  duplicate_transactions=OrderedDict(),
                                                  vote=VoteMetadata(),
                                                  signing_xmss=alice_xmss,
                                                  nonce=address_state_dict[staking_address].nonce + 1)
                        prev = tmp_block1.headerhash

                        res = chain.add_block(tmp_block1, address_state_dict, None)

                        address_state_dict[staking_address].increase_nonce()
                        address_state_dict[staking_address].balance += tmp_block1.block_reward

                        self.assertEqual(i, chain.height)  # FIXME: wrong name, it is not height but max_index

                        self.assertTrue(res)

                print(qrl.core.config.dev.disk_writes_after_x_blocks)
