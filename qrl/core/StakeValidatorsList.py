# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from pyqrllib.pyqrllib import bin2hstr
from qrl.core import config, helper, logger
from qrl.core.StakeValidator import StakeValidator
import simplejson as json
from collections import OrderedDict

from qrl.crypto.misc import sha256


class StakeValidatorsList:
    """
    Maintains the Stake validators list for current and next epoch
    """
    def __init__(self):
        self.sv_list = OrderedDict()
        self.next_sv_list = OrderedDict()
        self.hash_staker = OrderedDict()
        self.isOrderedLength = 0

    def __add__(self, sv_list, stake_txn):
        sv = StakeValidator(stake_txn)
        sv_list[stake_txn.txfrom] = sv
        return sv

    def update_hash_staker(self, sv):
        for chain_num in range(1):
            hash = sv.cache_hash[chain_num][-1]
            self.hash_staker[hash] = sv.stake_validator

    def calc_seed(self):
        epoch_seed = 0

        # seed for 1st block of next epoch will be XOR
        # of first_hash of all stake validators
        for staker in self.sv_list:
            sv = self.sv_list[staker]
            if not sv.first_hash:
                logger.error('sv.first_hash could not be empty %s', sv.first_hash)
                raise Exception
            epoch_seed |= int(bin2hstr(sv.first_hash), 16)

        return epoch_seed

    def add_sv(self, stake_txn):
        sv = self.__add__(self.sv_list, stake_txn)
        self.update_hash_staker(sv)

    def add_next_sv(self, stake_txn):
        self.__add__(self.next_sv_list, stake_txn)

    def get_sv_list(self, txfrom):
        if txfrom not in self.sv_list:
            return None
        return self.sv_list[txfrom]

    @staticmethod
    def select_target(last_block_headerhash):
        target_chain = 0
        for byte in last_block_headerhash:
            target_chain += byte

        target_chain = (target_chain - 1) % (config.dev.hashchain_nums - 1)  # 1 Primary hashchain size

        return target_chain

    def validate_hash(self, hash, blocknum, stake_address=None):
        epoch_blocknum = StakeValidator.get_epoch_blocknum(blocknum)
        if hash in self.hash_staker:
            if stake_address and stake_address != self.hash_staker[hash]:
                return False
            return True

        if stake_address:
            if stake_address not in self.sv_list:
                return False
            sv = self.sv_list[stake_address]
            return sv.validate_hash(hash, blocknum, self.hash_staker)

        tmp = hash
        count = epoch_blocknum
        while count >= -1:
            tmp = sha256(tmp)
            if tmp in self.hash_staker:
                stake_address = self.hash_staker[tmp]
                sv = self.sv_list[stake_address]
                sv.update(epoch_blocknum, hash, self.hash_staker)
                return True
            count -= 1

        return False

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
        logger.info('%s', self.__dict__)
        return helper.json_encode_complex(self)
