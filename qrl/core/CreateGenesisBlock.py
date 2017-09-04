# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from blockheader import BlockHeader
from qrl.crypto.misc import sha256
from qrl.core import config

genesis_info = dict()
genesis_info['Qcfdf7d621b49eeb57e7f7cc7b7218d6798e951e32f9c217512970ddac29dda8b7ac9'] = 1000000
genesis_info['Q809f7db42ac322d082823f1d79c2d95220acaf176c8f31bb53e3c474ccf41034e9be'] = 1000000
genesis_info['Qc0f401290da148f421eac9ed7f1992f3f581dd89a77b00da895b24c85b09a3afc780'] = 1000000
genesis_info['Qccf9bcbc30b2c125d4d36ad8888517874d28ccdc4a17c3bdd7b67743d103317b6342'] = 1000000
genesis_info['Q54610ec804e32e8cacfcc5786f89381816d0dbbe0145b26511b22d37347e641ab3e2'] = 1000000


class CreateGenesisBlock(object):  # first block has no previous header to reference..
    def __init__(self, chain):
        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain,
                                blocknumber=0,
                                hashchain_link='genesis',
                                prev_blockheaderhash=sha256(config.dev.genesis_prev_headerhash),
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
