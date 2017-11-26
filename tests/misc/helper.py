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
