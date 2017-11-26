# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from collections import OrderedDict, defaultdict
from typing import Dict  # noqa

from qrl.core import config, logger
from qrl.core.StakeValidator import StakeValidator
from qrl.core.Transaction import StakeTransaction


class StakeValidatorsTracker:
    """
    Maintains the Stake validators list for current and next epoch
    """

    def __init__(self):
        # Active stake validator objects
        self.sv_dict = OrderedDict()                    # type: Dict[bytes, StakeValidator]
        self.future_stake_addresses = dict()            # type: Dict[bytes, StakeValidator]

        self._expiry = defaultdict(set)  # Maintains the blocknumber as key at which Stake validator has to be expired
        self._future_sv_dict = defaultdict(set)
        self._total_stake_amount = 0  # Maintains the total stake amount by current stake validator

    def add_sv(self, balance, stake_txn: StakeTransaction, blocknumber):
        logger.debug("Adding %d %s %s", blocknumber, stake_txn.txfrom, stake_txn)
        if stake_txn.activation_blocknumber > blocknumber:
            self._add_future_sv(balance, stake_txn)
        else:
            self._activate_sv(balance, stake_txn)

    def _activate_sv(self, balance, stake_txn):
        if stake_txn.txfrom in self.sv_dict:
            logger.info('Stake Validator already in Current Staker, sv_dict')
            return
        sv = StakeValidator(balance, stake_txn)
        self.sv_dict[stake_txn.txfrom] = sv
        self._total_stake_amount += sv.balance
        self._expiry[stake_txn.activation_blocknumber + config.dev.blocks_per_epoch].add(stake_txn.txfrom)

    def _add_future_sv(self, balance, stake_txn):
        if stake_txn.txfrom in self._future_sv_dict:
            logger.info('Stake Validator already in Future Staker, future_sv_dict')
            return
        sv = StakeValidator(balance, stake_txn)
        self.future_stake_addresses[stake_txn.txfrom] = sv
        self._future_sv_dict[stake_txn.activation_blocknumber].add(sv)

    def _activate_future_sv(self, sv):
        self.sv_dict[sv.address] = sv
        self._total_stake_amount += sv.balance
        self._expiry[sv.activation_blocknumber + config.dev.blocks_per_epoch].add(sv.address)

    def update_sv(self, blocknumber):
        next_blocknumber = blocknumber + 1
        if next_blocknumber in self._expiry:
            for sv_addr in self._expiry[next_blocknumber]:
                self._total_stake_amount -= self.sv_dict[sv_addr].balance
                del self.sv_dict[sv_addr]
            del self._expiry[next_blocknumber]

        if next_blocknumber in self._future_sv_dict:
            sv_set = self._future_sv_dict[next_blocknumber]
            for sv in sv_set:
                self._activate_future_sv(sv)
                del self.future_stake_addresses[sv.address]
            del self._future_sv_dict[next_blocknumber]

    def validate_hash(self,
                      reveal_hash: bytes,
                      block_idx: int,
                      stake_address: bytes=None)->bool:

        if stake_address not in self.sv_dict:
            return False

        sv = self.sv_dict[stake_address]
        return sv.validate_hash(reveal_hash, block_idx)

    def get_stake_balance(self, stake_address: bytes)->int:
        if stake_address not in self.sv_dict:
            logger.warning('Stake address not found in Stake Validators Tracker')
            raise Exception

        return self.sv_dict[stake_address].balance

    def get_total_stake_amount(self):
        return self._total_stake_amount
