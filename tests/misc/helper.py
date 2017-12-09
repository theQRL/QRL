# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
import shutil
import tempfile

import os
from copy import deepcopy

from mock import mock

from qrl.core import config
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Transaction import TokenTransaction
from qrl.generated import qrl_pb2
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS


@contextlib.contextmanager
def set_wallet_dir(wallet_name):
    dst_dir = tempfile.mkdtemp()
    try:
        test_path = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(test_path, "..", "data", wallet_name)
        shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        config.user.wallet_path = dst_dir
        yield
    finally:
        shutil.rmtree(dst_dir)


@contextlib.contextmanager
def set_data_dir(data_name):
    dst_dir = tempfile.mkdtemp()
    try:
        test_path = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(test_path, "..", "data", data_name)
        shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        config.user.data_path = dst_dir
        yield
    finally:
        shutil.rmtree(dst_dir)


@contextlib.contextmanager
def mocked_genesis():
    custom_genesis_block = deepcopy(GenesisBlock())
    with mock.patch('qrl.core.GenesisBlock.GenesisBlock.instance'):
        GenesisBlock.instance = custom_genesis_block
        yield custom_genesis_block


def get_alice_xmss() -> XMSS:
    xmss_height = 6
    seed = bytes([i for i in range(48)])
    return XMSS(xmss_height, seed)


def get_bob_xmss() -> XMSS:
    xmss_height = 6
    seed = bytes([i + 5 for i in range(48)])
    return XMSS(xmss_height, seed)


def get_random_xmss() -> XMSS:
    xmss_height = 6
    return XMSS(xmss_height)


def qrladdress(address_seed: str) -> bytes:
    return b'Q' + sha256(address_seed.encode())


def get_token_transaction(xmss1, xmss2, amount1=400000000, amount2=200000000, fee=1) -> TokenTransaction:
    initial_balances = list()
    initial_balances.append(qrl_pb2.AddressAmount(address=xmss1.get_address().encode(),
                                                  amount=amount1))
    initial_balances.append(qrl_pb2.AddressAmount(address=xmss2.get_address().encode(),
                                                  amount=amount2))

    return TokenTransaction.create(addr_from=xmss1.get_address().encode(),
                                   symbol=b'QRL',
                                   name=b'Quantum Resistant Ledger',
                                   owner=xmss1.get_address().encode(),
                                   decimals=4,
                                   initial_balances=initial_balances,
                                   fee=fee,
                                   xmss_pk=xmss1.pk(),
                                   xmss_ots_index=xmss1.get_index())


def destroy_state():
    try:
        db_path = os.path.join(config.user.data_path, config.dev.db_name)
        shutil.rmtree(db_path)
    except FileNotFoundError:
        pass
