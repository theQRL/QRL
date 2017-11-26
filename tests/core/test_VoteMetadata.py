# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.VoteMetadata import VoteMetadata
from qrl.core.Transaction import Vote
from qrl.crypto.xmss import XMSS
from tests.misc.helper import get_alice_xmss, get_random_xmss

logger.initialize_default(force_console_output=True)


class TestVoteMetadata(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestVoteMetadata, self).__init__(*args, **kwargs)

    def test_add_vote1(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
        headerhash = b'ffff'
        vote = Vote.create(addr_from=alice_xmss.get_address().encode(),
                           blocknumber=0,
                           headerhash=headerhash,
                           xmss=slave_xmss)
        vote.sign(slave_xmss)

        stake_amount = 101.5012

        vote_metadata = VoteMetadata()
        self.assertNotIn(vote.txfrom, vote_metadata.stake_validator_vote)
        vote_metadata.add_vote(vote=vote, stake_amount=stake_amount)
        self.assertIn(vote.txfrom, vote_metadata.stake_validator_vote)
        self.assertEqual(stake_amount, vote_metadata.total_stake_amount)

    def test_add_vote2(self):
        validator_xmss1 = get_alice_xmss()
        slave_xmss1 = XMSS(validator_xmss1.height, validator_xmss1.get_seed())
        stake_amount1 = 101.5012
        headerhash1 = b'ffff'
        vote1 = Vote.create(addr_from=validator_xmss1.get_address().encode(),
                            blocknumber=0,
                            headerhash=headerhash1,
                            xmss=slave_xmss1)
        vote1.sign(slave_xmss1)

        vote_metadata = VoteMetadata()
        vote_metadata.add_vote(vote=vote1, stake_amount=stake_amount1)

        self.assertIn(vote1.txfrom, vote_metadata.stake_validator_vote)

        validator_xmss2 = get_random_xmss()
        slave_xmss2 = XMSS(validator_xmss2.height, validator_xmss2.get_seed())
        stake_amount2 = 10000
        headerhash2 = b'ffff'
        vote2 = Vote.create(addr_from=validator_xmss2.get_address().encode(),
                            blocknumber=0,
                            headerhash=headerhash2,
                            xmss=slave_xmss2)
        vote2.sign(slave_xmss2)

        vote_metadata.add_vote(vote=vote2, stake_amount=stake_amount2)

        self.assertIn(vote2.txfrom, vote_metadata.stake_validator_vote)

        total_stake_amount = stake_amount1 + stake_amount2
        self.assertEqual(total_stake_amount, vote_metadata.total_stake_amount)
