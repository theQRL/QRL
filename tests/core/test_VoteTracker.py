# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.VoteTracker import VoteTracker
from qrl.core.Transaction import Vote
from qrl.crypto.xmss import XMSS
from tests.misc.helper import get_alice_xmss, get_random_xmss

logger.initialize_default(force_console_output=True)


class TestVoteTracker(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestVoteTracker, self).__init__(*args, **kwargs)

    def test_add_vote1(self):
        vote_tracker = VoteTracker()
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
        headerhash = b'ffff'
        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                           blocknumber=0,
                           headerhash=headerhash,
                           xmss=slave_xmss)
        vote.sign(slave_xmss)

        stake_amount = 101.5012

        self.assertFalse(vote_tracker.is_already_voted(vote))

        self.assertTrue(vote_tracker.add_vote(vote, stake_amount))
        self.assertFalse(vote_tracker.add_vote(vote, stake_amount))

        self.assertTrue(vote_tracker.is_already_voted(vote))

        vote_metadata = vote_tracker.get_consensus()

        self.assertNotEquals(vote_metadata, None)
        self.assertIn(vote.addr_from, vote_metadata.stake_validator_vote)
        self.assertEqual(vote, vote_metadata.stake_validator_vote[vote.addr_from])
        self.assertEqual(stake_amount, vote_metadata.total_stake_amount)
        self.assertEqual(vote_tracker.get_consensus_headerhash(), headerhash)

    def test_add_vote2(self):
        vote_tracker = VoteTracker()

        validator_xmss1 = get_alice_xmss()
        slave_xmss1 = XMSS(validator_xmss1.height, validator_xmss1.get_seed())
        stake_amount1 = 101.5012
        headerhash1 = b'ffff'
        vote1 = Vote.create(addr_from=validator_xmss1.get_address().encode(),
                            blocknumber=0,
                            headerhash=headerhash1,
                            xmss=slave_xmss1)
        vote1.sign(slave_xmss1)

        self.assertTrue(vote_tracker.add_vote(vote1, stake_amount1))

        validator_xmss2 = get_random_xmss()
        slave_xmss2 = XMSS(validator_xmss2.height, validator_xmss2.get_seed())
        stake_amount2 = 10000
        headerhash2 = b'ffff'
        vote2 = Vote.create(addr_from=validator_xmss2.get_address().encode(),
                            blocknumber=0,
                            headerhash=headerhash2,
                            xmss=slave_xmss2)
        vote2.sign(slave_xmss2)

        self.assertTrue(vote_tracker.add_vote(vote2, stake_amount2))

        vote_metadata = vote_tracker.get_consensus()

        self.assertNotEquals(vote_metadata, None)

        total_stake_amount = stake_amount1 + stake_amount2
        self.assertEqual(total_stake_amount, vote_metadata.total_stake_amount)
        self.assertEqual(vote_tracker.get_consensus_headerhash(), headerhash1)

    def test_add_vote3(self):
        vote_tracker = VoteTracker()

        validator_xmss1 = get_alice_xmss()
        slave_xmss1 = XMSS(validator_xmss1.height, validator_xmss1.get_seed())
        stake_amount1 = 101.5012
        headerhash1 = b'ffff'
        vote1 = Vote.create(addr_from=validator_xmss1.get_address().encode(),
                            blocknumber=0,
                            headerhash=headerhash1,
                            xmss=slave_xmss1)
        vote1.sign(slave_xmss1)

        self.assertTrue(vote_tracker.add_vote(vote1, stake_amount1))

        validator_xmss2 = get_random_xmss()
        slave_xmss2 = XMSS(validator_xmss2.height, validator_xmss2.get_seed())
        headerhash2 = b'aaaa'
        stake_amount2 = 10000
        vote2 = Vote.create(addr_from=validator_xmss2.get_address().encode(),
                            blocknumber=0,
                            headerhash=headerhash2,
                            xmss=slave_xmss2)
        vote2.sign(slave_xmss2)

        self.assertTrue(vote_tracker.add_vote(vote2, stake_amount2))

        vote_metadata = vote_tracker.get_consensus()

        self.assertNotEquals(vote_metadata, None)

        self.assertEqual(stake_amount2, vote_metadata.total_stake_amount)
        self.assertNotEqual(vote_tracker.get_consensus_headerhash(), headerhash1)
        self.assertEqual(vote_tracker.get_consensus_headerhash(), headerhash2)
