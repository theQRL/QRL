# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import simplejson as json
from pyqrllib.pyqrllib import bin2hstr
from qrl.core import logger
from qrl.core.StakeValidator import StakeValidator
from collections import OrderedDict

from qrl.core.helper import ComplexEncoder
from qrl.crypto.misc import sha256


class StakeValidatorsList:
    """
    Maintains the Stake validators list for current and next epoch
    """
    def __init__(self):
        self.sv_list = OrderedDict()  # Active stake validator objects
        self.inactive_sv_list = OrderedDict()  # Inactive stake validator objects
        self.hash_staker = OrderedDict()
        self.isOrderedLength = 0

    def update_hash_staker(self, sv, blocknumber):
        hash = sv.cache_hash[blocknumber]
        self.hash_staker[hash] = sv.stake_validator

    def calc_seed(self):
        epoch_seed = 0

        for staker in self.sv_list:
            sv = self.sv_list[staker]
            if not sv.hash:
                logger.error('sv.hash could not be empty %s', sv.hash)
                raise Exception
            epoch_seed |= int(bin2hstr(sv.hash), 16)

        return epoch_seed

    def add_sv(self, stake_txn, blocknumber):
        sv = StakeValidator(stake_txn, blocknumber)
        self.sv_list[stake_txn.txfrom] = sv
        self.update_hash_staker(sv, blocknumber)

    def get_sv_list(self, txfrom):
        if txfrom not in self.sv_list:
            return None
        return self.sv_list[txfrom]

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

    def to_json(self):
        logger.info('%s', self.__dict__)
        return json.dumps(self, cls=ComplexEncoder)
