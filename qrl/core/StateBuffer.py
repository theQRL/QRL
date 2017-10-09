# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from pyqrllib.pyqrllib import hstr2bin, bin2hstr
from qrl.core import config
from qrl.crypto.misc import sha256
from copy import deepcopy


class StateBuffer:
    """
    Every new block coming in over the network modifies the local State in some way.
    StateBuffer is meant to be like a delta, storing what's changed.
    It stores the changes to address balances, nonces, pubhashes (used keys), and the list of stake validators.
    """
    def __init__(self):
        self.stake_validators_list = None
        self.stxn_state = {}  # key address, value [nonce, balance, pubhash]
        self.next_seed = None
        self.hash_chain = None

    def set_next_seed(self, winning_reveal, prev_seed):
        self.next_seed = bin2hstr(sha256(winning_reveal + hstr2bin(prev_seed)))

    @staticmethod
    def tx_to_list(txn_dict):
        tmp_sl = []
        for txfrom in txn_dict:
            st = txn_dict[txfrom]
            if not st[3]:  # rejecting ST having first_hash None
                continue
            tmp_sl.append(st)
        return tmp_sl

    def update(self, state, parent_state_buffer, block):
        # epoch mod to know if its the new epoch
        epoch_mod = block.blockheader.blocknumber % config.dev.blocks_per_epoch

        self.set_next_seed(block.blockheader.reveal_hash, parent_state_buffer.next_seed)
        self.hash_chain = deepcopy(parent_state_buffer.hash_chain)

        if epoch_mod == config.dev.blocks_per_epoch - 1:
            self.next_seed = bin2hstr(hex(self.stake_validators_list.calc_seed()))

        self.update_stxn_state(block, state)

    def update_stxn_state(self, block, state):
        stxn_state_keys = list(self.stxn_state.keys())
        for addr in stxn_state_keys:

            addr_list = state.state_get_address(addr)
            for i in range(0, len(addr_list[2])):
                addr_list[2][i] = tuple(addr_list[2][i])

            if self.stxn_state[addr][1] == addr_list[1] and self.stxn_state[addr][2] == addr_list[2]:
                del self.stxn_state[addr]
