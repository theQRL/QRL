# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config
import simplejson as json

from qrl.crypto.misc import sha256


class StakeValidator:
    """
    Stake Validator class to represent the each unique Stake Validator.

    Maintains the cache of successfully validated hashes, saves validation
    time by avoiding recalculation of the hash till the hash terminators.
    """
    def __init__(self, stake_validator, hashchain_terminators=None, first_hash=None, balance=0):
        self.buffer_size = 4  # Move size to dev configuration
        self.stake_validator = stake_validator
        self.balance = balance
        self.first_hash = first_hash
        self.hashchain_terminators = hashchain_terminators
        self.nonce = 0
        if hashchain_terminators:
            self.cache_hash = dict()
            for chain_num in range(config.dev.hashchain_nums):
                self.cache_hash[chain_num] = dict()
                self.cache_hash[chain_num][-1] = hashchain_terminators[chain_num]
            self.cache_hash[config.dev.hashchain_nums-1][-1] = self.first_hash

    def hash_to_terminator(self, hash, times):
        for _ in range(times):
            hash = sha256(hash)

        return hash

    # Saves the last X validated hash into the memory
    def update(self, epoch_blocknum, hash, target_chain, hash_staker):
        self.cache_hash[target_chain][epoch_blocknum] = hash
        hash_staker[hash] = self.stake_validator
        if len(self.cache_hash[target_chain]) > self.buffer_size:
            minimum_epoch_blocknum = min(self.cache_hash[target_chain])
            remove_hash = self.cache_hash[target_chain][minimum_epoch_blocknum]
            del hash_staker[remove_hash]
            del self.cache_hash[target_chain][minimum_epoch_blocknum]


    @staticmethod
    def get_epoch_blocknum(blocknum):
        epoch = blocknum // config.dev.blocks_per_epoch
        return blocknum - (epoch * config.dev.blocks_per_epoch)

    def validate_hash(self, hash, blocknum, hash_staker, target_chain=config.dev.hashchain_nums-1):
        epoch_blocknum = self.get_epoch_blocknum(blocknum)

        cache_blocknum = max(self.cache_hash[target_chain])
        times = epoch_blocknum - cache_blocknum
        terminator_expected = self.hash_to_terminator(hash, times)

        terminator_found = self.cache_hash[target_chain][cache_blocknum]

        if terminator_found != terminator_expected:
            return False

        self.update(epoch_blocknum, hash, target_chain, hash_staker)

        return True

    @staticmethod
    def to_object(json_sv):
        dict_sv = json.loads(json_sv)
        sv = StakeValidator(dict_sv['stake_validator'])
        sv.cache_hash = dict_sv['cache_hash']
        sv.first_hash = dict_sv['first_hash']
        sv.balance = dict_sv['balance']

        return sv

    def to_json(self):
        return json.dumps(self.__dict__)
