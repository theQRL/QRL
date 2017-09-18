# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import config, helper
from qrl.core.StakeValidator import StakeValidator
import simplejson as json
from collections import OrderedDict

from qrl.crypto.misc import sha256


class StakeValidatorsList:
    """
    Maintains the Stake validators list for current and next epoch

    Also maintains the threshold blocknumber for the stake validators
    of next epoch. This threshold value is compared when to validate
    the ST txn.
    """
    def __init__(self):
        self.sv_list = OrderedDict()
        self.next_sv_list = OrderedDict()
        self.hash_staker = OrderedDict()
        self.threshold = dict()
        self.isOrderedLength = 0

    def __add__(self, sv_list, txfrom, slave_public_key, hash, first_hash, balance):
        sv = StakeValidator(txfrom, slave_public_key, hash, first_hash, balance)
        sv_list[txfrom] = sv
        return sv

    def update_hash_staker(self, sv):
        for chain_num in range(config.dev.hashchain_nums):
            hash = sv.cache_hash[chain_num][-1]
            self.hash_staker[hash] = sv.stake_validator

    def calc_seed(self):
        epoch_seed = 0

        # seed for 1st block of next epoch will be XOR
        # of first_hash of all stake validators
        for staker in self.sv_list:
            sv = self.sv_list[staker]
            epoch_seed |= int(str(sv.first_hash), 16)

        return epoch_seed

    def add_sv(self, txfrom, slave_public_key, hash, first_hash, balance):
        sv = self.__add__(self.sv_list, txfrom, slave_public_key, hash, first_hash, balance)
        self.update_hash_staker(sv)

    def add_next_sv(self, txfrom, slave_public_key, hash, first_hash, balance):
        self.__add__(self.next_sv_list, txfrom, slave_public_key, hash, first_hash, balance)

    def get_sv_list(self, txfrom):
        if txfrom not in self.sv_list:
            return None
        return self.sv_list[txfrom]

    @staticmethod
    def select_target(last_block_headerhash):
        target_chain = 0
        for byte in last_block_headerhash:
            target_chain += ord(byte)

        target_chain = (target_chain - 1) % (config.dev.hashchain_nums - 1)  # 1 Primary hashchain size

        return target_chain

    def validate_hash(self, hash, blocknum, target_chain=config.dev.hashchain_nums-1, stake_address=None):
        epoch_blocknum = StakeValidator.get_epoch_blocknum(blocknum)
        if hash in self.hash_staker:
            if stake_address and stake_address != self.hash_staker[hash]:
                return False
            return True

        if stake_address:
            if stake_address not in self.sv_list:
                return False
            sv = self.sv_list[stake_address]
            return sv.validate_hash(hash, blocknum, self.hash_staker, target_chain)

        tmp = hash
        count = epoch_blocknum
        while count >= -1:
            tmp = sha256(tmp)
            if tmp in self.hash_staker:
                stake_address = self.hash_staker[tmp]
                sv = self.sv_list[stake_address]
                sv.update(epoch_blocknum, hash, target_chain, self.hash_staker)
                return True
            count -= 1

        return False

    def get_threshold(self, staker_address):
        if self.isOrderedLength != len(self.next_sv_list):
            self.next_sv_list = OrderedDict(sorted(iter(self.next_sv_list.items()), key=lambda sv: sv[1].balance))
            self.isOrderedLength = len(self.next_sv_list)
            mid_stakers = len(self.next_sv_list) // 2
            position = 0
            for staker in self.next_sv_list:
                if position < mid_stakers:
                    self.threshold[staker] = config.dev.low_staker_first_hash_block
                else:
                    self.threshold[staker] = config.dev.high_staker_first_hash_block
                position += 1

        return self.threshold[staker_address]

    def set_first_hash(self, staker_address, first_hash):
        self.next_sv_list[staker_address].first_hash = first_hash
        self.next_sv_list[staker_address].cache_hash[config.dev.hashchain_nums-1][-1] = first_hash

    # This should be called when we have moved to next epoch.
    def move_next_epoch(self):
        del self.sv_list
        self.sv_list = self.next_sv_list
        self.next_sv_list = OrderedDict()
        self.isOrderedLength = 0
        remove_stakers = []
        for staker in self.sv_list:
            if not self.sv_list[staker].first_hash:
                remove_stakers.append(staker)

        for staker in remove_stakers:
            del self.sv_list[staker]

        self.hash_staker = OrderedDict()
        for staker in self.sv_list:
            self.update_hash_staker(self.sv_list[staker])

        self.threshold = dict()

    @staticmethod
    def to_object(json_svl):
        dict_svl = json.loads(json_svl)
        svl = StakeValidatorsList()

        svl.sv_list = dict_svl['sv_list']
        for sv in svl.sv_list:
            svl.sv_list[sv] = StakeValidator.to_object(sv)

        svl.next_sv_list = dict_svl['next_sv_list']
        for sv in svl.next_sv_list:
            svl.sv_list[sv] = StakeValidator.to_object(sv)

        return svl

    def to_json(self):
        return helper.json_encode_complex(self)
