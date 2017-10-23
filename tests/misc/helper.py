# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
import shutil
import tempfile

import os

from qrl.core import config

@contextlib.contextmanager
def setWalletDir(wallet_name):
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
