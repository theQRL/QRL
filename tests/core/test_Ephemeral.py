# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from unittest import TestCase
from mock import mock
from pyqrllib.kyber import Kyber
from pyqrllib.dilithium import Dilithium

from qrl.crypto.xmss import XMSS
from qrl.crypto.misc import sha256
from qrl.core import logger, config
from qrl.core.Block import Block
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage, EphemeralChannelPayload
from qrl.crypto.aes import AES
from qrl.core.BufferedChain import BufferedChain
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.Chain import Chain
from qrl.core.Transaction import StakeTransaction, LatticePublicKey, Vote
from qrl.generated import qrl_pb2
from tests.misc.helper import set_wallet_dir, destroy_state, get_alice_xmss, get_random_xmss, mocked_genesis

logger.initialize_default()


class TestEphemeral(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestEphemeral, self).__init__(*args, **kwargs)

    def test_init(self):
        # TODO: Not much going on here..
        block = Block()
        self.assertIsNotNone(block)             # just to avoid warnings

    def test_add_4(self):
        destroy_state()
        with State() as state:
            with set_wallet_dir("test_wallet"):
                chain = Chain(state)
                buffered_chain = BufferedChain(chain)

                alice_xmss = get_alice_xmss()
                slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
                random_xmss1 = get_random_xmss()
                random_kyber1 = Kyber()
                random_dilithium1 = Dilithium()
                random_xmss2 = get_random_xmss()
                random_kyber2 = Kyber()
                random_dilithium2 = Dilithium()
                staking_address = bytes(alice_xmss.get_address())
                message = b'Hello World How are you?'
                prf512_seed = b'10192'

                # FIXME: Replace this with a call to create a hash_chain
                h0 = sha256(b'hashchain_seed')
                h1 = sha256(h0)
                h2 = sha256(h1)
                h3 = sha256(h2)
                h4 = sha256(h3)

                with mocked_genesis() as custom_genesis:
                    custom_genesis.genesis_balance.extend([qrl_pb2.GenesisBalance(address=alice_xmss.get_address(),
                                                                                  balance=700000000000000)])
                    stake_transaction = StakeTransaction.create(activation_blocknumber=1,
                                                                xmss=alice_xmss,
                                                                slavePK=slave_xmss.pk(),
                                                                hashchain_terminator=h4)
                    stake_transaction._data.nonce = 1  # FIXME: The test needs private access.. This is an API issue
                    stake_transaction.sign(alice_xmss)
                    custom_genesis.transactions.extend([stake_transaction.pbdata])

                    res = buffered_chain.genesis_loader(GenesisBlock())
                    self.assertTrue(res)

                    vote = Vote.create(blocknumber=0,
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

                    lattice_public_key_txn = LatticePublicKey.create(addr_from=random_xmss1.get_address(),
                                                                     fee=1,
                                                                     kyber_pk=random_kyber1.getPK(),
                                                                     dilithium_pk=random_dilithium1.getPK(),
                                                                     xmss_pk=random_xmss1.pk())
                    lattice_public_key_txn._data.nonce = 1
                    lattice_public_key_txn.sign(random_xmss1)

                    tmp_block1 = Block.create(staking_address=staking_address,
                                              block_number=1,
                                              reveal_hash=h3,
                                              prevblock_headerhash=GenesisBlock().headerhash,
                                              transactions=[lattice_public_key_txn],
                                              duplicate_transactions=OrderedDict(),
                                              vote=vote_metadata,
                                              signing_xmss=slave_xmss,
                                              nonce=1)

                    res = buffered_chain.add_block(block=tmp_block1)
                    self.assertTrue(res)

                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block1.timestamp + config.dev.minimum_minting_delay

                        encrypted_eph_message = EncryptedEphemeralMessage.create_channel(msg_id=lattice_public_key_txn.txhash,
                                                                                         ttl=time_mock.return_value,
                                                                                         ttr=0,
                                                                                         addr_from=random_xmss2.get_address(),
                                                                                         kyber_pk=random_kyber2.getPK(),
                                                                                         kyber_sk=random_kyber2.getSK(),
                                                                                         receiver_kyber_pk=random_kyber1.getPK(),
                                                                                         dilithium_pk=random_dilithium2.getPK(),
                                                                                         dilithium_sk=random_dilithium2.getSK(),
                                                                                         prf512_seed=prf512_seed,
                                                                                         data=message,
                                                                                         nonce=1)

                        buffered_chain.add_ephemeral_message(encrypted_eph_message)
                        eph_metadata = buffered_chain.collect_ephemeral_message(lattice_public_key_txn.txhash)

                        # Decrypting Payload

                        encrypted_eph_message = eph_metadata.encrypted_ephemeral_message_list[0]
                        encrypted_payload = encrypted_eph_message.payload

                        random_kyber1.kem_decode(encrypted_eph_message.channel.enc_aes256_symkey)
                        aes_key = bytes(random_kyber1.getMyKey())
                        myAES = AES(aes_key)
                        decrypted_payload = myAES.decrypt(encrypted_payload)
                        ephemeral_channel_payload = EphemeralChannelPayload.from_json(decrypted_payload)

                        self.assertEqual(ephemeral_channel_payload.prf512_seed, b'10192')
                        self.assertEqual(ephemeral_channel_payload.data, b'Hello World How are you?')

                        # TODO (cyyber): Add Ephemeral Testing code using Naive RNG
                        vote = Vote.create(blocknumber=1,
                                           headerhash=tmp_block1.headerhash,
                                           xmss=slave_xmss)
                        vote.sign(slave_xmss)
                        buffered_chain.add_vote(vote)
                        vote_metadata = buffered_chain.get_consensus(1)

                        tmp_block2 = Block.create(staking_address=staking_address,
                                                  block_number=2,
                                                  reveal_hash=h2,
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

                        vote = Vote.create(blocknumber=2,
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
                    address_state = chain.pstate.get_address(random_xmss1.get_address())

                    self.assertEqual(address_state.latticePK_list[0].kyber_pk, lattice_public_key_txn.kyber_pk)
                    self.assertEqual(address_state.latticePK_list[0].dilithium_pk, lattice_public_key_txn.dilithium_pk)
                    self.assertEqual(address_state.address, lattice_public_key_txn.txfrom)
                    # Need to move forward the time to align with block times
                    with mock.patch('qrl.core.ntp.getTime') as time_mock:
                        time_mock.return_value = tmp_block3.timestamp + config.dev.minimum_minting_delay

                        vote = Vote.create(blocknumber=3,
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

                    random_xmss1_state = chain.pstate._get_address_state(random_xmss1.get_address())

                    self.assertEqual(random_xmss1_state.balance, config.dev.default_account_balance - 1)
