# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import defaultdict
from qrl.core.Transaction import Vote
from qrl.core.VoteMetadata import VoteMetadata


class VoteTracker:
    def __init__(self):
        self.headerhash_voteMetadata = defaultdict(VoteMetadata)
        self.consensus_headerhash = None  # Keep track of the block headerhash having highest stake amount

    def add_vote(self, vote: Vote, stake_amount: float):
        self.headerhash_voteMetadata[vote.headerhash].add_vote(vote, stake_amount)

        if self.consensus_headerhash:
            if self.consensus_headerhash == vote.headerhash:
                return

            total_stake_amount = self.headerhash_voteMetadata[vote.headerhash].total_stake_amount
            consensus_total_stake_amount = self.headerhash_voteMetadata[self.consensus_headerhash].total_stake_amount
            if total_stake_amount < consensus_total_stake_amount:
                return

        self.consensus_headerhash = vote.headerhash

    def get_consensus(self) -> VoteMetadata:
        return self.headerhash_voteMetadata[self.consensus_headerhash]