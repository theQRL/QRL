# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger, config
from qrl.core.StakeValidator import StakeValidator
from qrl.core.Transaction import StakeTransaction
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from tests.misc.helper import get_alice_xmss

logger.initialize_default(force_console_output=True)


class TestStakeValidator(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestStakeValidator, self).__init__(*args, **kwargs)

    def test_empty_terminator(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
        stake_transaction = StakeTransaction.create(activation_blocknumber=0,
                                                    xmss=alice_xmss,
                                                    slavePK=slave_xmss.pk())

        stake_transaction._data.stake.hash = bytes([])
        with self.assertRaises(ValueError):
            StakeValidator(0, stake_transaction)

    def test_invalid_balance(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
        stake_transaction = StakeTransaction.create(activation_blocknumber=0,
                                                    xmss=alice_xmss,
                                                    slavePK=slave_xmss.pk())

        with self.assertRaises(ValueError):
            StakeValidator(config.dev.minimum_staking_balance_required - 1, stake_transaction)

    def test_negative_balance(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())
        stake_transaction = StakeTransaction.create(activation_blocknumber=0,
                                                    xmss=alice_xmss,
                                                    slavePK=slave_xmss.pk())

        with self.assertRaises(ValueError):
            StakeValidator(-1, stake_transaction)

    def test_create(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())

        staking_address = bytes(alice_xmss.get_address().encode())

        h0 = sha256(b'hashchain_seed')
        h1 = sha256(h0)
        h2 = sha256(h1)

        stake_transaction = StakeTransaction.create(activation_blocknumber=0,
                                                    xmss=alice_xmss,
                                                    slavePK=slave_xmss.pk(),
                                                    hashchain_terminator=h2)

        sv = StakeValidator(100, stake_transaction)

        self.assertEqual(staking_address, sv.address)
        self.assertEqual(slave_xmss.pk(), sv.slave_public_key)
        self.assertEqual(h2, sv.terminator_hash)

        self.assertEqual(100, sv.balance)
        self.assertEqual(0, sv.nonce)
        self.assertFalse(sv.is_banned)
        self.assertTrue(sv.is_active)

    def test_create2(self):
        alice_xmss = get_alice_xmss()
        slave_xmss = XMSS(alice_xmss.height, alice_xmss.get_seed())

        h0 = sha256(b'hashchain_seed')
        h1 = sha256(h0)
        h2 = sha256(h1)
        h3 = sha256(h2)

        stake_transaction = StakeTransaction.create(activation_blocknumber=0,
                                                    xmss=alice_xmss,
                                                    slavePK=slave_xmss.pk(),
                                                    hashchain_terminator=h3)

        sv = StakeValidator(100, stake_transaction)
        self.assertTrue(sv.validate_hash(h0, 2))
        self.assertTrue(sv.validate_hash(h2, 0))

        self.assertTrue(sv.validate_hash(h2, 0))
        self.assertTrue(sv.validate_hash(h1, 1))
        self.assertTrue(sv.validate_hash(h0, 2))
