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
        self.isOrderedLength = 0

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

    def get_sv_list(self, txfrom):
        if txfrom not in self.sv_list:
            return None
        return self.sv_list[txfrom]

    def validate_hash(self, hasharg, blocknum, stake_address=None):
        if stake_address not in self.sv_list:
            return False
        sv = self.sv_list[stake_address]
        return sv.validate_hash(hasharg, blocknum, self.hash_staker)

    def to_json(self):
        logger.info('%s', self.__dict__)
        return json.dumps(self, cls=ComplexEncoder)
