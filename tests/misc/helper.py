# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
import os
import shutil
import tempfile
import time
from copy import deepcopy

import simplejson as json
from mock import mock
from pyqrllib.pyqrllib import XmssFast
from pyqrllib.pyqrllib import bin2hstr, hstr2bin

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2

logger.initialize_default()


def replacement_getTime():
    return int(time.time())


@contextlib.contextmanager
def set_default_balance_size(new_value=100 * int(config.dev.shor_per_quanta)):
    old_value = config.dev.default_account_balance
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
        yield dst_dir
    finally:
        shutil.rmtree(dst_dir)
        config.user.wallet_dir = prev_val


@contextlib.contextmanager
def set_qrl_dir(data_name):
    dst_dir = tempfile.mkdtemp()
    prev_val = config.user.qrl_dir
    try:
        test_path = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(test_path, "..", "data")
        src_dir = os.path.join(data_dir, data_name)
        shutil.rmtree(dst_dir)
        shutil.copytree(src_dir, dst_dir)
        shutil.copy(os.path.join(data_dir, 'core', 'genesis.yml'), dst_dir)
        shutil.copy(os.path.join(data_dir, 'core', 'config.yml'), dst_dir)
        config.user.qrl_dir = dst_dir
        yield dst_dir
    finally:
        shutil.rmtree(dst_dir)
        config.user.qrl_dir = prev_val


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
        config.user = config.UserConfig(True)
        yield
    finally:
        shutil.rmtree(dst_dir)
        GenesisBlock.instance = None
        config.user.qrl_dir = prev_val


def get_some_address(idx=0) -> bytes:
    seed = bytearray([i for i in range(48)])
    seed[0] = idx
    xmss = XMSS(XmssFast(seed, 4))
    return xmss.address


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
