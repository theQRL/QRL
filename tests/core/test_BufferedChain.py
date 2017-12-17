# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from unittest import TestCase
from pyqrllib.pyqrllib import bin2hstr

from mock import Mock, MagicMock, mock

from qrl.core import logger, config
from qrl.core.Block import Block
from qrl.core.BufferedChain import BufferedChain
from qrl.core.Chain import Chain
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.Transaction import StakeTransaction, Vote, TransferTokenTransaction, TransferTransaction
from qrl.core.Wallet import Wallet
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2
from tests.misc.helper import set_wallet_dir, get_alice_xmss, mocked_genesis, get_random_xmss, get_token_transaction, destroy_state

logger.initialize_default()


class TestBufferedChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBufferedChain, self).__init__(*args, **kwargs)

    def test_create(self):
        with set_wallet_dir("test_wallet"):
            # FIXME: cross-dependency
            chain = Mock(spec=Chain)
            chain.height = 0
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
        destroy_state()
        with State() as state:
            with set_wallet_dir("test_wallet"):
                chain = Mock(spec=Chain)
                chain.height = 0
                chain.get_block = MagicMock(return_value=None)
                chain.wallet = Wallet()
                chain.pstate = state

                buffered_chain = BufferedChain(chain)

                b0 = buffered_chain.get_block(0)
                buffered_chain._chain.get_block.assert_called()
                self.assertIsNone(b0)

                tmp_block = Block()
                res = buffered_chain.add_block(block=tmp_block)
                self.assertFalse(res)

    def test_add_genesis(self):
        destroy_state()
        with State() as state:
            with set_wallet_dir("test_wallet"):
                chain = Mock(spec=Chain)
                chain.height = 0
                chain.get_block = MagicMock(return_value=None)
                chain.wallet = Wallet()
                chain.pstate = state

                buffered_chain = BufferedChain(chain)

                b0 = buffered_chain.get_block(0)
                buffered_chain._chain.get_block.assert_called()
                self.assertIsNone(b0)

                res = buffered_chain.add_block(block=GenesisBlock())
                self.assertTrue(res)

    def test_add_2(self):
        destroy_state()
        with State() as state:
            with set_wallet_dir("test_wallet"):
                chain = Chain(state)
                buffered_chain = BufferedChain(chain)

                alice_xmss = get_alice_xmss()
                slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
                staking_address = bytes(alice_xmss.get_address().encode())

                h0 = sha256(b'hashchain_seed')
                h1 = sha256(h0)

                with mocked_genesis() as custom_genesis:
                    custom_genesis.genesis_balance.extend([qrl_pb2.GenesisBalance(address=alice_xmss.get_address(),
                                                                                  balance=700000000000000)])

                    res = buffered_chain.add_block(block=custom_genesis)
                    self.assertTrue(res)

                    stake_transaction = StakeTransaction.create(activation_blocknumber=1,
                                                                xmss=alice_xmss,
                                                                slavePK=slave_xmss.pk(),
                                                                hashchain_terminator=h1)
                    vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                       blocknumber=0,
                                       headerhash=custom_genesis.headerhash,
                                       xmss=slave_xmss)
                    vote.sign(slave_xmss)
                    buffered_chain.add_vote(vote)
                    vote_metadata = buffered_chain.get_consensus(0)

                    # FIXME: The test needs private access.. This is an API issue
                    stake_transaction._data.nonce = 1

                    stake_transaction.sign(alice_xmss)

                    chain.pstate.stake_validators_tracker.add_sv(balance=700000000000000,
                                                                 stake_txn=stake_transaction,
                                                                 blocknumber=1)
                    sv = chain.pstate.stake_validators_tracker.sv_dict[staking_address]
                    self.assertEqual(0, sv.nonce)

                    tmp_block = Block.create(staking_address=bytes(alice_xmss.get_address().encode()),
                                             block_number=1,
                                             reveal_hash=h0,
                                             prevblock_headerhash=custom_genesis.headerhash,
                                             transactions=[stake_transaction],
                                             duplicate_transactions=OrderedDict(),
                                             vote=vote_metadata,
                                             signing_xmss=alice_xmss,
                                             nonce=1)

                    res = buffered_chain.add_block(block=tmp_block)
                    self.assertTrue(res)

    def test_add_3(self):
        destroy_state()
        with State() as state:
            with set_wallet_dir("test_wallet"):
                chain = Chain(state)
                buffered_chain = BufferedChain(chain)

                alice_xmss = get_alice_xmss()
                slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())

                staking_address = bytes(alice_xmss.get_address().encode())

                # FIXME: Replace this with a call to create a hash_chain
                h0 = sha256(b'hashchain_seed')
                h1 = sha256(h0)
                h2 = sha256(h1)
                h3 = sha256(h2)

                with mocked_genesis() as custom_genesis:
                    custom_genesis.genesis_balance.extend([qrl_pb2.GenesisBalance(address=alice_xmss.get_address(),
                                                                                  balance=700000000000000)])

                    res = buffered_chain.add_block(block=GenesisBlock())
                    self.assertTrue(res)
                    stake_transaction = StakeTransaction.create(activation_blocknumber=1,
                                                                xmss=alice_xmss,
                                                                slavePK=slave_xmss.pk(),
                                                                hashchain_terminator=h3)
                    stake_transaction._data.nonce = 1  # FIXME: The test needs private access.. This is an API issue
                    stake_transaction.sign(alice_xmss)

                    vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                       blocknumber=0,
                                       headerhash=GenesisBlock().headerhash,
                                       xmss=slave_xmss)
                    vote.sign(slave_xmss)
                    buffered_chain.add_vote(vote)
                    vote_metadata = buffered_chain.get_consensus(0)

                    chain.pstate.stake_validators_tracker.add_sv(balance=700000000000000,
                                                                 stake_txn=stake_transaction,
                                                                 blocknumber=1)

                    sv = chain.pstate.stake_validators_tracker.sv_dict[staking_address]
                    self.assertEqual(0, sv.nonce)

                    tmp_block1 = Block.create(staking_address=staking_address,
                                              block_number=1,
                                              reveal_hash=h2,
                                              prevblock_headerhash=GenesisBlock().headerhash,
                                              transactions=[stake_transaction],
                                              duplicate_transactions=OrderedDict(),
                                              vote=vote_metadata,
                                              signing_xmss=slave_xmss,
                                              nonce=1)

                    res = buffered_chain.add_block(block=tmp_block1)
                    self.assertTrue(res)

                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block1.timestamp + config.dev.minimum_minting_delay

                        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                           blocknumber=1,
                                           headerhash=tmp_block1.headerhash,
                                           xmss=slave_xmss)
                        vote.sign(slave_xmss)
                        buffered_chain.add_vote(vote)
                        vote_metadata = buffered_chain.get_consensus(1)

                        tmp_block2 = Block.create(staking_address=staking_address,
                                                  block_number=2,
                                                  reveal_hash=h1,
                                                  prevblock_headerhash=tmp_block1.headerhash,
                                                  transactions=[],
                                                  duplicate_transactions=OrderedDict(),
                                                  vote=vote_metadata,
                                                  signing_xmss=slave_xmss,
                                                  nonce=2)

                    res = buffered_chain.add_block(block=tmp_block2)
                    self.assertTrue(res)

                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block2.timestamp + config.dev.minimum_minting_delay

                        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                           blocknumber=2,
                                           headerhash=tmp_block2.headerhash,
                                           xmss=slave_xmss)
                        vote.sign(slave_xmss)
                        buffered_chain.add_vote(vote)
                        vote_metadata = buffered_chain.get_consensus(2)

                        tmp_block3 = Block.create(staking_address=staking_address,
                                                  block_number=3,
                                                  reveal_hash=h0,
                                                  prevblock_headerhash=tmp_block2.headerhash,
                                                  transactions=[],
                                                  duplicate_transactions=OrderedDict(),
                                                  vote=vote_metadata,
                                                  signing_xmss=slave_xmss,
                                                  nonce=3)

                    res = buffered_chain.add_block(block=tmp_block3)
                    self.assertTrue(res)

    def test_add_4(self):
        destroy_state()
        with State() as state:
            with set_wallet_dir("test_wallet"):
                chain = Chain(state)
                buffered_chain = BufferedChain(chain)

                alice_xmss = get_alice_xmss()
                slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
                random_xmss1 = get_random_xmss()
                random_xmss2 = get_random_xmss()
                staking_address = bytes(alice_xmss.get_address().encode())

                # FIXME: Replace this with a call to create a hash_chain
                h0 = sha256(b'hashchain_seed')
                h1 = sha256(h0)
                h2 = sha256(h1)
                h3 = sha256(h2)
                h4 = sha256(h3)

                with mocked_genesis() as custom_genesis:
                    custom_genesis.genesis_balance.extend([qrl_pb2.GenesisBalance(address=alice_xmss.get_address(),
                                                                                  balance=700000000000000)])

                    res = buffered_chain.add_block(block=GenesisBlock())
                    self.assertTrue(res)
                    stake_transaction = StakeTransaction.create(activation_blocknumber=1,
                                                                xmss=alice_xmss,
                                                                slavePK=slave_xmss.pk(),
                                                                hashchain_terminator=h4)
                    stake_transaction._data.nonce = 1  # FIXME: The test needs private access.. This is an API issue
                    stake_transaction.sign(alice_xmss)

                    vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                       blocknumber=0,
                                       headerhash=GenesisBlock().headerhash,
                                       xmss=slave_xmss)
                    vote.sign(slave_xmss)
                    buffered_chain.add_vote(vote)
                    vote_metadata = buffered_chain.get_consensus(0)

                    chain.pstate.stake_validators_tracker.add_sv(balance=700000000000000,
                                                                 stake_txn=stake_transaction,
                                                                 blocknumber=1)

                    sv = chain.pstate.stake_validators_tracker.sv_dict[staking_address]
                    self.assertEqual(0, sv.nonce)

                    # Token Transaction to create a token for test
                    token_transaction = get_token_transaction(random_xmss1, random_xmss2)
                    token_transaction._data.nonce = 1
                    token_transaction.sign(random_xmss1)

                    # Transfer Token Transaction
                    transfer_token1 = TransferTokenTransaction.create(addr_from=random_xmss1.get_address().encode(),
                                                                      token_txhash=token_transaction.txhash,
                                                                      addr_to=alice_xmss.get_address().encode(),
                                                                      amount=100000000,
                                                                      fee=1,
                                                                      xmss_pk=random_xmss1.pk(),
                                                                      xmss_ots_index=random_xmss1.get_index())
                    transfer_token1._data.nonce = 2
                    transfer_token1.sign(random_xmss1)

                    transfer_token2 = TransferTokenTransaction.create(addr_from=random_xmss2.get_address().encode(),
                                                                      token_txhash=token_transaction.txhash,
                                                                      addr_to=alice_xmss.get_address().encode(),
                                                                      amount=200000000,
                                                                      fee=1,
                                                                      xmss_pk=random_xmss2.pk(),
                                                                      xmss_ots_index=random_xmss2.get_index())
                    transfer_token2._data.nonce = 1
                    transfer_token2.sign(random_xmss2)

                    # Transfer Coin Transaction
                    transfer_transaction = TransferTransaction.create(addr_from=random_xmss1.get_address().encode(),
                                                                      addr_to=random_xmss2.get_address().encode(),
                                                                      amount=10,
                                                                      fee=1,
                                                                      xmss_pk=random_xmss1.pk(),
                                                                      xmss_ots_index=random_xmss1.get_index())
                    transfer_transaction._data.nonce = 3
                    transfer_transaction.sign(random_xmss1)

                    tmp_block1 = Block.create(staking_address=staking_address,
                                              block_number=1,
                                              reveal_hash=h3,
                                              prevblock_headerhash=GenesisBlock().headerhash,
                                              transactions=[stake_transaction, token_transaction],
                                              duplicate_transactions=OrderedDict(),
                                              vote=vote_metadata,
                                              signing_xmss=slave_xmss,
                                              nonce=1)

                    res = buffered_chain.add_block(block=tmp_block1)
                    self.assertTrue(res)

                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block1.timestamp + config.dev.minimum_minting_delay

                        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                           blocknumber=1,
                                           headerhash=tmp_block1.headerhash,
                                           xmss=slave_xmss)
                        vote.sign(slave_xmss)
                        buffered_chain.add_vote(vote)
                        vote_metadata = buffered_chain.get_consensus(1)

                        tmp_block2 = Block.create(staking_address=staking_address,
                                                  block_number=2,
                                                  reveal_hash=h2,
                                                  prevblock_headerhash=tmp_block1.headerhash,
                                                  transactions=[transfer_token1, transfer_token2, transfer_transaction],
                                                  duplicate_transactions=OrderedDict(),
                                                  vote=vote_metadata,
                                                  signing_xmss=slave_xmss,
                                                  nonce=2)

                    res = buffered_chain.add_block(block=tmp_block2)
                    self.assertTrue(res)

                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block2.timestamp + config.dev.minimum_minting_delay

                        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                           blocknumber=2,
                                           headerhash=tmp_block2.headerhash,
                                           xmss=slave_xmss)
                        vote.sign(slave_xmss)
                        buffered_chain.add_vote(vote)
                        vote_metadata = buffered_chain.get_consensus(2)

                        tmp_block3 = Block.create(staking_address=staking_address,
                                                  block_number=3,
                                                  reveal_hash=h1,
                                                  prevblock_headerhash=tmp_block2.headerhash,
                                                  transactions=[],
                                                  duplicate_transactions=OrderedDict(),
                                                  vote=vote_metadata,
                                                  signing_xmss=slave_xmss,
                                                  nonce=3)

                    res = buffered_chain.add_block(block=tmp_block3)
                    self.assertTrue(res)

                    chain = buffered_chain._chain
                    random_xmss1_state = chain.pstate._get_address_state(random_xmss1.get_address().encode())
                    random_xmss2_state = chain.pstate._get_address_state(random_xmss2.get_address().encode())

                    self.assertEqual(random_xmss1_state.tokens[bin2hstr(token_transaction.txhash).encode()], 400000000)
                    self.assertEqual(random_xmss2_state.tokens[bin2hstr(token_transaction.txhash).encode()], 200000000)

                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block3.timestamp + config.dev.minimum_minting_delay

                        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                                           blocknumber=3,
                                           headerhash=tmp_block3.headerhash,
                                           xmss=slave_xmss)
                        vote.sign(slave_xmss)
                        buffered_chain.add_vote(vote)
                        vote_metadata = buffered_chain.get_consensus(3)

                        tmp_block4 = Block.create(staking_address=staking_address,
                                                  block_number=4,
                                                  reveal_hash=h0,
                                                  prevblock_headerhash=tmp_block3.headerhash,
                                                  transactions=[],
                                                  duplicate_transactions=OrderedDict(),
                                                  vote=vote_metadata,
                                                  signing_xmss=slave_xmss,
                                                  nonce=4)

                    res = buffered_chain.add_block(block=tmp_block4)
                    self.assertTrue(res)

                    token_metadata = buffered_chain.get_token_metadata(token_transaction.txhash)

                    self.assertEqual(token_metadata.token_txhash, token_transaction.txhash)
                    self.assertEqual(len(token_metadata.transfer_token_tx_hashes), 3)
                    self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)

                    random_xmss1_state = chain.pstate._get_address_state(random_xmss1.get_address().encode())
                    random_xmss2_state = chain.pstate._get_address_state(random_xmss2.get_address().encode())
                    alice_state = chain.pstate._get_address_state(alice_xmss.get_address().encode())

                    self.assertEqual(random_xmss1_state.tokens[bin2hstr(token_transaction.txhash).encode()], 300000000)
                    self.assertEqual(random_xmss2_state.tokens[bin2hstr(token_transaction.txhash).encode()], 0)
                    self.assertEqual(alice_state.tokens[bin2hstr(token_transaction.txhash).encode()], 300000000)
                    self.assertEqual(random_xmss1_state.balance, config.dev.default_account_balance - 13)
                    self.assertEqual(random_xmss2_state.balance, config.dev.default_account_balance + 9)
