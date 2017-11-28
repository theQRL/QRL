# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Dict  # noqa

from qrl.core.AddressState import AddressState  # noqa
from qrl.core.Block import Block

from qrl.core.formulas import score
from qrl.crypto.misc import sha256


# OLD [block_buffer, state_buffer]

class BlockMetadata(object):
    # FIXME: This is not really a buffer. Understand concept and refactor
    def __init__(self,
                 block: Block,
                 hash_chain,
                 epoch_seed,
                 balance: int):

        self.block = block
        self.score = 0
        self.isVoted = False

        if self.block.block_number > 0:
            self.score = self._block_score(epoch_seed, balance)

        self.epoch_seed = epoch_seed
        self.next_seed = self.get_next_seed()

        self.stake_validators_tracker = None
        self.address_state_dict = {}  # type: Dict[bytes, AddressState]
        self.hash_chain = hash_chain

    def set_voted(self):
        self.isVoted = True

    @property
    def sorting_key(self):
        return tuple((self.score, self.block.headerhash))

    def _block_score(self, seed, balance):
        # FIXME: Review + Duplicated code
        score_val = score(stake_address=self.block.stake_selector,
                          reveal_one=self.block.reveal_hash,
                          balance=balance,
                          seed=seed,
                          verbose=False)

        return score_val

    def get_next_seed(self) -> bytes:
        return sha256(self.block.reveal_hash + self.epoch_seed)

    def update_stxn_state(self, pstate):
        address_state_keys = list(self.address_state_dict.keys())
        for addr in address_state_keys:
            addr_state = pstate.get_address(addr)

            if self.address_state_dict[addr].balance == addr_state.balance and \
                    self.address_state_dict[addr].pubhashes == addr_state.pubhashes:
                del self.address_state_dict[addr]
