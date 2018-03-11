# coding=utf-8
from __future__ import print_function

from qrl.generated import qrl_pb2
from qrl.core import config
from qrl.core.Block import Block
from qrl.crypto.xmss import XMSS


seed = b'\x01\x03\x00\x8e\xf4\xd7\x00\x05\xc2.\x83P\xceJ\xc9)\xfb\x98+\xff\x84\x12-\x9b]*X\xe96\xd70n\xc9\x0e\x0f\xdd\xb7\x97^\x9c)\xca\xcf\x1fp\x9d\x02\xcb\xdeU\xd4'

dist_xmss = XMSS.from_extended_seed(seed)

block = Block.create(block_number=0,
                     prevblock_headerhash=config.dev.genesis_prev_headerhash,
                     transactions=[],
                     signing_xmss=dist_xmss,
                     master_address=dist_xmss.address,
                     nonce=0)

block._data.genesis_balance.MergeFrom([qrl_pb2.GenesisBalance(address=config.dev.coinbase_address,
                                                              balance=105000000000000000)])

with open('genesis.json', 'w') as f:
    f.write(block.to_json())
