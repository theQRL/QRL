# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import defaultdict
from typing import Optional
from qrl.core.Transaction import Vote
from qrl.core.VoteMetadata import VoteMetadata


class VoteTracker:
    """
    Maintains the Stake weight of each multiple headerhash of same blocknumber,
    also keeps track of highest stake headerhash
    """

    def __init__(self):
        self._headerhash_voteMetadata = defaultdict(VoteMetadata)
        self._consensus_headerhash = None  # Keep track of the block headerhash having highest stake amount
        self.voted_stake_validators = set()

    def add_vote(self, vote: Vote, stake_amount: float):
        if self.is_already_voted(vote):
            return False

        self._headerhash_voteMetadata[vote.headerhash].add_vote(vote, stake_amount)
        self.voted_stake_validators.add(vote.addr_from)

        if self._consensus_headerhash:
            if self._consensus_headerhash == vote.headerhash:
                return True

            total_stake_amount = self._headerhash_voteMetadata[vote.headerhash].total_stake_amount
            consensus_total_stake_amount = self._headerhash_voteMetadata[self._consensus_headerhash].total_stake_amount
            if total_stake_amount < consensus_total_stake_amount:
                return True

        self._consensus_headerhash = vote.headerhash

        return True

    def is_already_voted(self, vote):
        if vote.addr_from in self.voted_stake_validators:
            return True

        return False

    def get_consensus(self) -> Optional[VoteMetadata]:
        if not self._consensus_headerhash:
            return None

        return self._headerhash_voteMetadata[self._consensus_headerhash]

    def get_consensus_headerhash(self) -> Optional[bytes]:
        return self._consensus_headerhash
