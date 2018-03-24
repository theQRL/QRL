# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
import os
import shutil
import tempfile
from copy import deepcopy
from math import log, ceil

import simplejson as json
import time
from mock import mock, MagicMock, Mock
import pyqrllib
from pyqrllib.dilithium import Dilithium
from pyqrllib.kyber import Kyber
from pyqrllib.pyqrllib import QRLHelper, shake128, QRLDescriptor, SHA2_256, XmssFast
from pyqrllib.pyqrllib import bin2hstr, hstr2bin
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.PoWValidator import PoWValidator
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.Transaction import TokenTransaction, SlaveTransaction
from qrl.core.qrlnode import QRLNode
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2
from tests.misc.EphemeralPayload import EphemeralMessagePayload, EphemeralChannelPayload
from tests.misc.aes import AES
from tests.misc.random_number_generator import RNG


@contextlib.contextmanager
def set_default_balance_size(new_value=100 * int(config.dev.shor_per_quanta)):
    old_value = config.dev.block_timeseries_size
    try:
        config.dev.default_account_balance = new_value
        yield
    finally:
        config.dev.default_account_balance = old_value


@contextlib.contextmanager
def set_wallet_dir(wallet_name):
    dst_dir = tempfile.mkdtemp()
    prev_val = config.user.wallet_dir
    try:
        test_path = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(test_path, "..", "data", wallet_name)
        shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        config.user.wallet_dir = dst_dir
        yield
    finally:
        shutil.rmtree(dst_dir)
        config.user.wallet_dir = prev_val


@contextlib.contextmanager
def set_data_dir(data_name):
    dst_dir = tempfile.mkdtemp()
    prev_val = config.user.data_dir
    try:

        test_path = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(test_path, "..", "data", data_name)
        shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        config.user.data_dir = dst_dir
        yield
    finally:
        shutil.rmtree(dst_dir)
        config.user.data_dir = prev_val


@contextlib.contextmanager
def qrlnode_with_mock_blockchain(num_blocks):
    start_time = time.time()
    with mock.patch('qrl.core.misc.ntp.getTime') as ntp_mock, \
            set_data_dir('no_data'), \
            State() as state, \
            mock.patch('time.time') as time_mock:  # noqa
        time_mock.return_value = start_time
        ntp_mock.return_value = start_time

        state.get_measurement = MagicMock(return_value=10000000)

        required_height = ceil(log(num_blocks, 2))
        required_height = int(required_height + required_height % 2)

        alice_xmss = get_alice_xmss(xmss_height=required_height)
        bob_xmss = get_bob_xmss()

        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)

        chain_manager._difficulty_tracker = Mock()
        dt = DifficultyTracker()
        tmp_difficulty = StringToUInt256('2')
        tmp_target = dt.get_target(tmp_difficulty)

        chain_manager._difficulty_tracker.get = MagicMock(return_value=(tmp_difficulty, tmp_target))

        block_prev = state.get_block(genesis_block.headerhash)

        for block_idx in range(1, num_blocks):
            transactions = []
            if block_idx == 1:
                slave_tx = SlaveTransaction.create(slave_pks=[bob_xmss.pk],
                                                   access_types=[0],
                                                   fee=0,
                                                   xmss_pk=alice_xmss.pk)
                slave_tx.sign(alice_xmss)
                slave_tx._data.nonce = 2
                transactions = [slave_tx]

            time_mock.return_value = time_mock.return_value + 60
            ntp_mock.return_value = ntp_mock.return_value + 60

            block_new = Block.create(block_number=block_idx,
                                     prevblock_headerhash=block_prev.headerhash,
                                     transactions=transactions,
                                     signing_xmss=alice_xmss,
                                     master_address=alice_xmss.address,
                                     nonce=block_idx)

            while not PoWValidator().validate_mining_nonce(state, block_new.blockheader, False):
                block_new.set_mining_nonce(block_new.mining_nonce + 1)

            chain_manager.add_block(block_new)
            block_prev = block_new

        qrlnode = QRLNode(state, slaves=[])
        qrlnode.set_chain_manager(chain_manager)

        yield qrlnode


def read_data_file(filename):
    test_path = os.path.dirname(os.path.abspath(__file__))
    src_file = os.path.join(test_path, "..", "data", filename)
    with open(src_file, 'r') as f:
        return f.read()


@contextlib.contextmanager
def mocked_genesis():
    custom_genesis_block = deepcopy(GenesisBlock())
    with mock.patch('qrl.core.GenesisBlock.GenesisBlock.instance'):
        GenesisBlock.instance = custom_genesis_block
        yield custom_genesis_block


@contextlib.contextmanager
def clean_genesis():
    data_name = "no_data"
    dst_dir = tempfile.mkdtemp()
    prev_val = config.user.qrl_dir
    try:
        GenesisBlock.instance = None
        test_path = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(test_path, "..", "data", data_name)
        shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        config.user.qrl_dir = dst_dir
        _ = GenesisBlock()  # noqa
        config.user.qrl_dir = prev_val
        yield
    finally:
        shutil.rmtree(dst_dir)
        GenesisBlock.instance = None
        config.user.qrl_dir = prev_val


def get_alice_xmss(xmss_height=6) -> XMSS:
    seed = bytes([i for i in range(48)])
    return XMSS(XmssFast(seed, xmss_height))


def get_bob_xmss(xmss_height=6) -> XMSS:
    seed = bytes([i + 5 for i in range(48)])
    return XMSS(XmssFast(seed, xmss_height))


def get_slave_xmss() -> XMSS:
    xmss_height = 6
    seed = bytes([i + 10 for i in range(48)])
    return XMSS(XmssFast(seed, xmss_height))


def get_random_xmss(xmss_height=6) -> XMSS:
    return XMSS.from_height(xmss_height)


def qrladdress(address_seed_str: str) -> bytes:
    extended_seed = QRLDescriptor(SHA2_256, pyqrllib.pyqrllib.XMSS, 4, 0).getBytes() + \
                    shake128(48, address_seed_str.encode())
    return bytes(QRLHelper.getAddress(extended_seed))


def get_token_transaction(xmss1, xmss2, amount1=400000000, amount2=200000000, fee=1) -> TokenTransaction:
    initial_balances = list()
    initial_balances.append(qrl_pb2.AddressAmount(address=xmss1.address,
                                                  amount=amount1))
    initial_balances.append(qrl_pb2.AddressAmount(address=xmss2.address,
                                                  amount=amount2))

    return TokenTransaction.create(symbol=b'QRL',
                                   name=b'Quantum Resistant Ledger',
                                   owner=xmss1.address,
                                   decimals=4,
                                   initial_balances=initial_balances,
                                   fee=fee,
                                   xmss_pk=xmss1.pk)


def destroy_state():
    try:
        db_path = os.path.join(config.user.data_dir, config.dev.db_name)
        shutil.rmtree(db_path)
    except FileNotFoundError:
        pass


def create_ephemeral_channel(msg_id: bytes,
                             ttl: int,
                             ttr: int,
                             addr_from: bytes,
                             kyber_pk: bytes,
                             kyber_sk: bytes,
                             receiver_kyber_pk: bytes,
                             dilithium_pk: bytes,
                             dilithium_sk: bytes,
                             prf512_seed: bytes,
                             data: bytes,
                             nonce: int):
    sender_kyber = Kyber(kyber_pk, kyber_sk)
    sender_kyber.kem_encode(receiver_kyber_pk)
    enc_aes256_symkey = bytes(sender_kyber.getCypherText())
    aes256_symkey = sender_kyber.getMyKey()
    aes = AES(bytes(aes256_symkey))
    sender_dilithium = Dilithium(dilithium_pk, dilithium_sk)

    ephemeral_data = EphemeralChannelPayload.create(addr_from,
                                                    prf512_seed,
                                                    data)

    ephemeral_data.dilithium_sign(msg_id, ttl, ttr, enc_aes256_symkey, nonce, sender_dilithium)

    encrypted_ephemeral_message = EncryptedEphemeralMessage()

    encrypted_ephemeral_message._data.msg_id = msg_id
    encrypted_ephemeral_message._data.ttl = ttl
    encrypted_ephemeral_message._data.ttr = ttr
    encrypted_ephemeral_message._data.channel.enc_aes256_symkey = enc_aes256_symkey
    encrypted_ephemeral_message._data.nonce = nonce
    encrypted_ephemeral_message._data.payload = aes.encrypt(ephemeral_data.to_json().encode())

    return encrypted_ephemeral_message


def create_ephemeral_message(ttl: int,
                             ttr: int,
                             addr_from: bytes,
                             kyber_pk: bytes,
                             kyber_sk: bytes,
                             receiver_kyber_pk: bytes,
                             prf512_seed: bytes,
                             seq: int,
                             data: bytes,
                             nonce: int):
    sender_kyber = Kyber(kyber_pk, kyber_sk)
    sender_kyber.kem_encode(receiver_kyber_pk)

    aes256_symkey = sender_kyber.getMyKey()
    aes = AES(aes256_symkey)

    ephemeral_data = EphemeralMessagePayload.create(addr_from, data)

    encrypted_ephemeral_message = EncryptedEphemeralMessage()

    encrypted_ephemeral_message._data.msg_id = RNG.generate(prf512_seed, seq)
    encrypted_ephemeral_message._data.ttl = ttl
    encrypted_ephemeral_message._data.ttr = ttr
    encrypted_ephemeral_message._data.nonce = nonce
    encrypted_ephemeral_message._data.payload = aes.encrypt(ephemeral_data.to_json())

    return encrypted_ephemeral_message


def get_slaves(alice_ots_index, txn_nonce):
    # [master_address: bytes, slave_seeds: list, slave_txn: json]

    slave_xmss = get_slave_xmss()
    alice_xmss = get_alice_xmss()

    alice_xmss.set_ots_index(alice_ots_index)
    slave_txn = SlaveTransaction.create([slave_xmss.pk],
                                        [1],
                                        0,
                                        alice_xmss.pk)
    slave_txn._data.nonce = txn_nonce
    slave_txn.sign(alice_xmss)

    slave_data = json.loads(json.dumps([bin2hstr(alice_xmss.address), [slave_xmss.extended_seed], slave_txn.to_json()]))
    slave_data[0] = bytes(hstr2bin(slave_data[0]))
    return slave_data


def get_random_master():
    random_master = get_random_xmss(config.dev.xmss_tree_height)
    slave_data = json.loads(json.dumps([bin2hstr(random_master.address), [random_master.extended_seed], None]))
    slave_data[0] = bytes(hstr2bin(slave_data[0]))
    return slave_data
