# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from collections import OrderedDict, defaultdict
from pyqrllib.pyqrllib import bin2hstr
from qrl.core import logger, config
from qrl.core.StakeValidator import StakeValidator


class StakeValidatorsList:
    """
    Maintains the Stake validators list for current and next epoch
    """
    def __init__(self):
        self.sv_list = OrderedDict()  # Active stake validator objects
        self.expiry = defaultdict(set)  # Maintains the blocknumber as key at which Stake validator has to be expired
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
        self.expiry[blocknumber + config.dev.blocks_per_epoch].append(stake_txn.txfrom)

    def remove_expired_sv(self, blocknumber):
        if blocknumber not in self.expiry:
            return

        for sv_addr in self.expiry[blocknumber]:
            del self.sv_list[sv_addr]

        del self.expiry[blocknumber]

    def get_sv_list(self, txfrom):
        if txfrom not in self.sv_list:
            return None
        return self.sv_list[txfrom]

    def validate_hash(self, hasharg, blocknum, stake_address=None):
        if stake_address not in self.sv_list:
            return False
        sv = self.sv_list[stake_address]
        return sv.validate_hash(hasharg, blocknum)