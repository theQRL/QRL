# coding=utf-8
from __future__ import print_function

import json

import qrl.crypto.xmss
from qrl.core import config

num_accounts = 100
file_name = "aws_wallet"

wallets = {}
for i in range(num_accounts):
    print("Generating (", i + 1, "/", num_accounts, ")")
    wallet = qrl.crypto.xmss.XMSS(tree_height=config.dev.xmss_tree_height, seed=None)
    wallets[wallet.get_address()] = wallet.get_mnemonic()

with open(file_name, 'w') as f:
    json.dump(wallets, f)  # , encoding = "ISO-8859-1")
