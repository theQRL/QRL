# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from pyqrllib.pyqrllib import bin2hstr
from qrl.core import config, logger
import simplejson as json

from qrl.crypto.misc import sha256


class StakeValidator:
    """
    Stake Validator class to represent the each unique Stake Validator.

    Maintains the cache of successfully validated hashes, saves validation
    time by avoiding recalculation of the hash till the hash terminators.
    """
    def __init__(self, stake_txn, entry_blocknumber):
        self.buffer_size = 4  # Move size to dev configuration
        self.stake_validator = stake_txn.txfrom
        self.slave_public_key = stake_txn.slave_public_key
        self.balance = stake_txn.balance
        self.hash = stake_txn.hash
        self.entry_blocknumber = entry_blocknumber  # Blocknumber at which ST txn was added into block

        self.finalized_blocknumber = stake_txn.finalized_blocknumber
        self.finalized_headerhash = stake_txn.finalized_headerhash

        self.nonce = 0
        self.is_banned = False
        self.is_active = True  # Flag that represents if the stakevalidator has been deactivated by destake txn

        if self.hash:
            self.cache_hash = dict()
            self.cache_hash[entry_blocknumber] = self.hash

    def hash_to_terminator(self, hash, times):
        for _ in range(times):
            hash = sha256(bin2hstr(tuple(hash)).encode())

        return hash

    # Saves the last X validated hash into the memory
    def update(self, epoch_blocknum, hash, hash_staker):
        self.cache_hash[epoch_blocknum] = hash
        hash_staker[hash] = self.stake_validator
        if len(self.cache_hash) > self.buffer_size:
            minimum_epoch_blocknum = min(self.cache_hash)
            remove_hash = self.cache_hash[minimum_epoch_blocknum]
            del hash_staker[remove_hash]
            del self.cache_hash[minimum_epoch_blocknum]

    @staticmethod
    def get_epoch_blocknum(blocknum):
        epoch = blocknum // config.dev.blocks_per_epoch
        return blocknum - (epoch * config.dev.blocks_per_epoch)

    def validate_hash(self, hash, blocknum, hash_staker):

        cache_blocknum = max(self.cache_hash)
        times = blocknum - cache_blocknum

        terminator_expected = tuple(self.hash_to_terminator(hash, times))
        terminator_found = tuple(self.cache_hash[cache_blocknum])

        if terminator_found != terminator_expected:
            return False

        self.update(blocknum, hash, hash_staker)

        return True

    def to_json(self):
        return json.dumps(self.__dict__)
