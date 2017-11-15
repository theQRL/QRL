# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core.Transaction import Vote


class VoteMetadata:
    def __init__(self):
        self.stake_validator_vote = dict()
        self.total_stake_amount = 0

    def add_vote(self, vote: Vote, stake_amount: float):
        if vote.addr_from in self.stake_validator_vote:
            return

        self.stake_validator_vote[vote.addr_from] = vote
        self.total_stake_amount += stake_amount
