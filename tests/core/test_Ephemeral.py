# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import mock, Mock
from pyqrllib.dilithium import Dilithium
from pyqrllib.kyber import Kyber
from pyqrllib.pyqrllib import XmssFast
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.PoWValidator import PoWValidator
from qrl.core.State import State
from qrl.core.Transaction import LatticePublicKey
from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2
from tests.misc.EphemeralPayload import EphemeralChannelPayload
from tests.misc.aes import AES
from tests.misc.helper import get_alice_xmss, get_random_xmss, mocked_genesis, create_ephemeral_channel, \
    set_qrl_dir

logger.initialize_default()


class TestEphemeral(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestEphemeral, self).__init__(*args, **kwargs)

    def test_init(self):
        # TODO: Not much going on here..
        block = Block()
        self.assertIsNotNone(block)  # just to avoid warnings

    @mock.patch("qrl.core.DifficultyTracker.DifficultyTracker.get")
    def test_add_4(self, mock_difficulty_tracker_get):
        with set_qrl_dir('wallet_ver1'):
            with State() as state:
                with mocked_genesis() as custom_genesis:
                    chain_manager = ChainManager(state)

                    chain_manager._difficulty_tracker = Mock()
                    tmp_difficulty = StringToUInt256('2')
                    tmp_target = DifficultyTracker.get_target(tmp_difficulty)
                    mock_difficulty_tracker_get.return_value = [tmp_difficulty, tmp_target]

                    alice_xmss = get_alice_xmss()
                    slave_xmss = XMSS(XmssFast(alice_xmss.seed, alice_xmss.height))
                    random_xmss1 = get_random_xmss()
                    random_kyber1 = Kyber()
                    random_dilithium1 = Dilithium()
                    random_xmss2 = get_random_xmss()
                    random_kyber2 = Kyber()
                    random_dilithium2 = Dilithium()

                    message = b'Hello World How are you?'
                    prf512_seed = b'10192'

                    custom_genesis.genesis_balance.extend(
                        [qrl_pb2.GenesisBalance(address=random_xmss1.address, balance=65000000000000000)])
                    custom_genesis.genesis_balance.extend(
                        [qrl_pb2.GenesisBalance(address=random_xmss2.address, balance=65000000000000000)])
                    chain_manager.load(custom_genesis)

                    with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
                        time_mock.return_value = 1615270948

                        lattice_public_key_txn = LatticePublicKey.create(fee=1,
                                                                         kyber_pk=random_kyber1.getPK(),
                                                                         dilithium_pk=random_dilithium1.getPK(),
                                                                         xmss_pk=random_xmss1.pk)
                        lattice_public_key_txn._data.nonce = 1
                        lattice_public_key_txn.sign(random_xmss1)
                        genesis_block = GenesisBlock()
                        tmp_block1 = Block.create(block_number=1,
                                                  prev_block_headerhash=genesis_block.headerhash,
                                                  prev_block_timestamp=genesis_block.timestamp,
                                                  transactions=[lattice_public_key_txn],
                                                  miner_address=slave_xmss.address)

                        #  Mine the nonce
                        while not PoWValidator().validate_mining_nonce(state, tmp_block1.blockheader, False):
                            tmp_block1.set_nonces(tmp_block1.mining_nonce + 1, 0)

                        self.assertTrue(tmp_block1.validate(state, {}))
                        res = chain_manager.add_block(block=tmp_block1)
                        self.assertTrue(res)

                        # Need to move forward the time to align with block times
                        time_mock.return_value += config.dev.minimum_minting_delay * 2

                        encrypted_eph_message = create_ephemeral_channel(msg_id=lattice_public_key_txn.txhash,
                                                                         ttl=time_mock.return_value,
                                                                         ttr=0,
                                                                         addr_from=random_xmss2.address,
                                                                         kyber_pk=random_kyber2.getPK(),
                                                                         kyber_sk=random_kyber2.getSK(),
                                                                         receiver_kyber_pk=random_kyber1.getPK(),
                                                                         dilithium_pk=random_dilithium2.getPK(),
                                                                         dilithium_sk=random_dilithium2.getSK(),
                                                                         prf512_seed=prf512_seed,
                                                                         data=message,
                                                                         nonce=1)

                        chain_manager.state.update_ephemeral(encrypted_eph_message)
                        eph_metadata = chain_manager.state.get_ephemeral_metadata(lattice_public_key_txn.txhash)

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

                        tmp_block2 = Block.create(block_number=2,
                                                  prev_block_headerhash=tmp_block1.headerhash,
                                                  prev_block_timestamp=tmp_block1.timestamp,
                                                  transactions=[],
                                                  miner_address=slave_xmss.address)

                        #  Mine the nonce
                        while not PoWValidator().validate_mining_nonce(state, tmp_block2.blockheader, False):
                            tmp_block2.set_nonces(tmp_block2.mining_nonce + 1, 0)

                        self.assertTrue(tmp_block2.validate(state, {}))
                        res = chain_manager.add_block(block=tmp_block2)
                        self.assertTrue(res)

                        # Need to move forward the time to align with block times
                        time_mock.return_value += config.dev.minimum_minting_delay * 2

                        tmp_block3 = Block.create(block_number=3,
                                                  prev_block_headerhash=tmp_block2.headerhash,
                                                  prev_block_timestamp=tmp_block1.timestamp,
                                                  transactions=[],
                                                  miner_address=slave_xmss.address)

                        #  Mine the nonce
                        while not PoWValidator().validate_mining_nonce(state, tmp_block3.blockheader, False):
                            tmp_block3.set_nonces(tmp_block3.mining_nonce + 1, 0)

                        self.assertTrue(tmp_block3.validate(state, {}))
                        res = chain_manager.add_block(block=tmp_block3)
                        self.assertTrue(res)

                        time_mock.return_value += config.dev.minimum_minting_delay

                        tmp_block4 = Block.create(block_number=4,
                                                  prev_block_headerhash=tmp_block3.headerhash,
                                                  prev_block_timestamp=tmp_block1.timestamp,
                                                  transactions=[],
                                                  miner_address=slave_xmss.address)

                        #  Mine the nonce
                        while not PoWValidator().validate_mining_nonce(state, tmp_block4.blockheader, False):
                            tmp_block4.set_nonces(tmp_block4.mining_nonce + 1, 0)

                        self.assertTrue(tmp_block4.validate(state, {}))
                        res = chain_manager.add_block(block=tmp_block4)
                        self.assertTrue(res)

                        address_state = chain_manager.get_address(random_xmss1.address)

                        self.assertEqual(address_state.latticePK_list[0].kyber_pk, lattice_public_key_txn.kyber_pk)
                        self.assertEqual(address_state.latticePK_list[0].dilithium_pk,
                                         lattice_public_key_txn.dilithium_pk)

                        self.assertEqual(address_state.address, lattice_public_key_txn.addr_from)

                        random_xmss1_state = chain_manager.get_address(random_xmss1.address)

                        self.assertEqual(64999999999999999, random_xmss1_state.balance)
