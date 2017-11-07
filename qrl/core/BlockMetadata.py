# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core.Block import Block
from pyqrllib.pyqrllib import str2bin, bin2hstr
from qrl.crypto.misc import sha256
from copy import deepcopy


# OLD [block_buffer, state_buffer]

class BlockMetadata(object):
    # FIXME: This is not really a buffer. Understand concept and refactor
    def __init__(self,
                 block: Block,
                 chain,
                 seed,
                 balance: int):

        self.block = block
        self.score = self._block_score(chain, seed, balance)

        self.stake_validators_tracker = None
        self.stxn_state = {}  # key address, value [nonce, balance, pubhash]
        self.next_seed = None
        self.hash_chain = None

    @property
    def sorting_key(self):
        return tuple(self.score, self.block.headerhash)

    def _block_score(self, chain, seed, balance):
        seed = int(str(seed), 16)
        score_val = chain.score(stake_address=self.block.stake_selector,
                                reveal_one=self.block.reveal_hash,
                                balance=balance,
                                seed=seed,
                                verbose=False)

        return score_val

    def set_next_seed(self, winning_reveal, prev_seed):
        self.next_seed = bin2hstr(sha256(tuple(winning_reveal) + str2bin(prev_seed)))

    @staticmethod
    def tx_to_list(txn_dict):
        tmp_sl = []
        for txfrom in txn_dict:
            st = txn_dict[txfrom]
            if not st[3]:  # rejecting ST having first_hash None
                continue
            tmp_sl.append(st)
        return tmp_sl

    def update(self, pstate, parent_state_buffer, block):
        self.set_next_seed(block.reveal_hash, parent_state_buffer.next_seed)
        self.hash_chain = deepcopy(parent_state_buffer.hash_chain)
        self.update_stxn_state(pstate)

    def update_stxn_state(self, pstate):
        stxn_state_keys = list(self.stxn_state.keys())
        for addr in stxn_state_keys:
            addr_state = pstate.get_address(addr)

            if self.stxn_state[addr].balance == addr_state.balance and self.stxn_state[addr].pubhashes == addr_state.pubhashes:
                del self.stxn_state[addr]