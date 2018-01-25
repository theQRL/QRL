# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
import shutil
import tempfile

import os
import simplejson as json

from copy import deepcopy

from mock import mock
from pyqrllib.kyber import Kyber
from pyqrllib.dilithium import Dilithium

from qrl.core import config
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Transaction import TokenTransaction, SlaveTransaction
from qrl.generated import qrl_pb2
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from tests.misc.random_number_generator import RNG
from tests.misc.aes import AES
from tests.misc.EphemeralPayload import EphemeralMessagePayload, EphemeralChannelPayload


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


def get_alice_xmss() -> XMSS:
    xmss_height = 6
    seed = bytes([i for i in range(48)])
    return XMSS(xmss_height, seed)


def get_bob_xmss() -> XMSS:
    xmss_height = 6
    seed = bytes([i + 5 for i in range(48)])
    return XMSS(xmss_height, seed)


def get_slave_xmss() -> XMSS:
    xmss_height = 6
    seed = bytes([i + 10 for i in range(48)])
    return XMSS(xmss_height, seed)


def get_random_xmss(xmss_height=6) -> XMSS:
    return XMSS(xmss_height)


def qrladdress(address_seed: str) -> bytes:
    return b'Q' + sha256(address_seed.encode())


def get_token_transaction(xmss1, xmss2, amount1=400000000, amount2=200000000, fee=1) -> TokenTransaction:
    initial_balances = list()
    initial_balances.append(qrl_pb2.AddressAmount(address=xmss1.get_address(),
                                                  amount=amount1))
    initial_balances.append(qrl_pb2.AddressAmount(address=xmss2.get_address(),
                                                  amount=amount2))

    return TokenTransaction.create(addr_from=xmss1.get_address(),
                                   symbol=b'QRL',
                                   name=b'Quantum Resistant Ledger',
                                   owner=xmss1.get_address(),
                                   decimals=4,
                                   initial_balances=initial_balances,
                                   fee=fee,
                                   xmss_pk=xmss1.pk(),
                                   xmss_ots_index=xmss1.get_index())


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

    alice_xmss.set_index(alice_ots_index)
    slave_txn = SlaveTransaction.create(alice_xmss.get_address(),
                                        [slave_xmss.pk()],
                                        [1],
                                        0,
                                        alice_xmss.pk(),
                                        alice_ots_index)
    slave_txn._data.nonce = txn_nonce
    slave_txn.sign(alice_xmss)

    return json.loads(json.dumps([alice_xmss.get_address(), [slave_xmss.get_seed()], slave_txn.to_json()]))


def get_random_master():
    random_master = get_random_xmss(config.dev.xmss_tree_height)
    return json.loads(json.dumps([random_master.get_address(), [random_master.get_seed()], None]))
