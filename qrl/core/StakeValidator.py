# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from google.protobuf.json_format import MessageToJson, Parse

from qrl.core import config
from qrl.core.Transaction import StakeTransaction
from qrl.generated import qrl_pb2
from qrl.crypto.misc import sha256_n


class StakeValidator:
    """
    Stake Validator class to represent each unique Stake Validator

    Maintains the cache of successfully validated hashes, saves validation
    time by avoiding recalculation of the hash till the hash terminators.
    """

    def __init__(self, stakevalidator_protobuf=None):
        self._data = stakevalidator_protobuf
        if not self._data:
            self._data = qrl_pb2.StakeValidator()

    @property
    def pbdata(self):
        return self._data

    @property
    def address(self) -> bytes:
        return self._data.address

    @property
    def slave_public_key(self) -> bytes:
        return self._data.slave_public_key

    @property
    def terminator_hash(self) -> bytes:
        return self._data.terminator_hash

    @property
    def balance(self) -> int:
        return self._data.balance

    @property
    def is_banned(self) -> bool:
        return self._data.is_banned

    @property
    def is_active(self) -> bool:
        return self._data.is_active

    @property
    def nonce(self) -> int:
        return self._data.nonce

    @property
    def activation_blocknumber(self) -> int:
        return self._data.activation_blocknumber

    def increase_nonce(self):
        self._data.nonce += 1

    @staticmethod
    def _hash_to_terminator(reveal_hash: bytes, times: int) -> bytes:
        return sha256_n(reveal_hash, times)

    @staticmethod
    def create(balance: int,
               stake_txn: StakeTransaction):

        stakevalidator = StakeValidator()

        stakevalidator._data.address = stake_txn.txfrom
        stakevalidator._data.slave_public_key = stake_txn.slave_public_key

        stakevalidator._data.terminator_hash = stake_txn.hash
        if not stakevalidator._data.terminator_hash:
            raise ValueError("terminator hash cannot be empty")

        stakevalidator._data.balance = balance
        if balance < config.dev.minimum_staking_balance_required:
            raise ValueError("balance should be at least {}".format(config.dev.minimum_staking_balance_required))

        stakevalidator._data.activation_blocknumber = stake_txn.activation_blocknumber

        stakevalidator._data.nonce = 0
        stakevalidator._data.is_banned = False
        stakevalidator._data.is_active = True  # Flag that represents if the stakevalidator has been deactivated by destake txn

        return stakevalidator

    def validate_hash(self, reveal_hash: bytes, block_idx: int) -> bool:
        # FIXME: Measure with a profiler if we really need a cache here

        times = block_idx - self.activation_blocknumber + 1
        terminator_found = self._hash_to_terminator(reveal_hash, times)
        terminator_expected = self.terminator_hash

        return terminator_found == terminator_expected

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.StakeValidator()
        Parse(json_data, pbdata)
        return StakeValidator(pbdata)

    def to_json(self):
        return MessageToJson(self._data)
