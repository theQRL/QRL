# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrlcore.block import BlockHeader
from qrlcore.merkle import sha256


genesis_info = dict()
genesis_info['Qf3dadd056aa76b192fcde016521840b401ab031f550552bc9568ad109bc0efeda304'] = 1000000
genesis_info['Q244e4a5a2ee825d3d095b826529a9f282c723c2c29366c469fdb401018f4eda596a0'] = 1000000
genesis_info['Qa4d14fd8f9d0eeaa92d21a21c8d77ea07475d9a4c0baa87ac753aa6aecde8d3e9d88'] = 1000000
genesis_info['Q3d24023dc38cafb29aaa9ae7753b8979b31706a319ee6306f47e03751bd128fcbe09'] = 1000000
genesis_info['Qc03edc9e020579d2b2d09795f23ff43f1e487a569cfe343c993731fb50f44c2322a7'] = 1000000
genesis_info['Q185c158b962619fe64041f15b7e0f30cc3de5d8a2f9dbefec1e3b3d4758d1bf5475e'] = 1000000


class CreateGenesisBlock(object):  # first block has no previous header to reference..
    def __init__(self, chain):
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain, blocknumber=0, hashchain_link='genesis',
                                prev_blockheaderhash=sha256('quantum resistant ledger'),
                                hashedtransactions=sha256('0'),
                                reveal_list=[],
                                vote_hashes=[])
        self.transactions = []
        self.stake = []
        self.state = []
        for key in genesis_info:
            self.state.append([key, [0, genesis_info[key] * 100000000, []]])

        self.stake_list = []
        for stake in self.state:
            self.stake_list.append(stake[0])

        self.stake_seed = '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'