# coding=utf-8
from __future__ import print_function

from pyqrllib.pyqrllib import hstr2bin

from qrl.generated import qrl_pb2
from qrl.core import config
from qrl.core.Block import Block
from qrl.crypto.xmss import XMSS


seed = bytes(hstr2bin(input('Enter extended hexseed: ')))

dist_xmss = XMSS.from_extended_seed(seed)

block = Block.create(block_number=0,
                     prevblock_headerhash=config.dev.genesis_prev_headerhash,
                     transactions=[],
                     miner_address=dist_xmss.address)

block.set_mining_nonce(0)

block._data.genesis_balance.MergeFrom([qrl_pb2.GenesisBalance(address=config.dev.coinbase_address,
                                                              balance=105000000000000000)])

k = block.blockheader.to_json()

with open('genesis.json', 'w') as f:
    f.write(block.to_json())
