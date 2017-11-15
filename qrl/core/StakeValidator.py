# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config
from qrl.core.Transaction import StakeTransaction
from qrl.crypto.misc import sha256_n


class StakeValidator:
    """
    Stake Validator class to represent each unique Stake Validator

    Maintains the cache of successfully validated hashes, saves validation
    time by avoiding recalculation of the hash till the hash terminators.
    """

    def __init__(self,
                 balance: int,
                 stake_txn: StakeTransaction):

        self._address = stake_txn.txfrom
        self._slave_public_key = stake_txn.slave_public_key

        self._terminator_hash = stake_txn.hash
        if not self.terminator_hash:
            raise ValueError("terminator hash cannot be empty")

        self._balance = balance
        if balance < config.dev.minimum_staking_balance_required:
            raise ValueError("balance should be at least {}".format(config.dev.minimum_staking_balance_required))

        self.activation_blocknumber = stake_txn.activation_blocknumber

        self._nonce = 0
        self._is_banned = False
        self._is_active = True  # Flag that represents if the stakevalidator has been deactivated by destake txn

    @property
    def address(self) -> bytes:
        return self._address

    @property
    def slave_public_key(self) -> bytes:
        return self._slave_public_key

    @property
    def terminator_hash(self) -> bytes:
        return self._terminator_hash

    @property
    def balance(self) -> int:
        return self._balance

    @property
    def is_banned(self) -> bool:
        return self._is_banned

    @property
    def is_active(self) -> bool:
        return self._is_active

    @property
    def nonce(self) -> int:
        return self._nonce

    def increase_nonce(self):
        self._nonce += 1

    @staticmethod
    def _hash_to_terminator(reveal_hash: bytes, times: int) -> bytes:
        return sha256_n(reveal_hash, times)

    def validate_hash(self, reveal_hash: bytes, block_idx: int) -> bool:
        # FIXME: Measure with a profiler if we really need a cache here

        times = block_idx - self.activation_blocknumber + 1
        terminator_found = self._hash_to_terminator(reveal_hash, times)
        terminator_expected = self.terminator_hash

        return terminator_found == terminator_expected
