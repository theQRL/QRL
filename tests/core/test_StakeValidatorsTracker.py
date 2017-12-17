# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.core.StakeValidatorsTracker import StakeValidatorsTracker
from qrl.core.Transaction import StakeTransaction
from qrl.crypto.xmss import XMSS
from tests.misc.helper import get_alice_xmss

logger.initialize_default()


class TestStakeValidatorsTracker(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestStakeValidatorsTracker, self).__init__(*args, **kwargs)

    def test_create1(self):
        stake_validators_tracker = StakeValidatorsTracker.create()
        self.assertIsInstance(stake_validators_tracker, StakeValidatorsTracker)

    def test_add_sv(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())

        stake_validators_tracker = StakeValidatorsTracker.create()

        stake_transaction = StakeTransaction.create(0, alice_xmss, slave_xmss.pk(), b'1111')
        stake_validators_tracker.add_sv(100, stake_transaction, 1)

        balance = stake_validators_tracker.get_stake_balance(alice_xmss.get_address().encode())
        self.assertEqual(100, balance)

        total_stake_amount = stake_validators_tracker.get_total_stake_amount()
        self.assertEqual(100, total_stake_amount)
        stake_validators_tracker.to_json()

    def test_add_future_sv(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())

        stake_validators_tracker = StakeValidatorsTracker.create()

        stake_transaction = StakeTransaction.create(10, alice_xmss, slave_xmss.pk(), b'1111')
        stake_validators_tracker.add_sv(100, stake_transaction, 1)

        total_stake_amount = stake_validators_tracker.get_total_stake_amount()
        self.assertNotEqual(100, total_stake_amount)
