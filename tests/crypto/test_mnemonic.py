# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

import pytest

from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr
from qrl.core import logger
from qrl.crypto.hmac_drbg import SEED
from qrl.crypto.mnemonic import seed_to_mnemonic, mnemonic_to_seed
from qrl.crypto.words import wordlist
from tests.crypto.known_values import S1, S1_Mne

logger.initialize_default(force_console_output=True)


class TestMnemonic(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMnemonic, self).__init__(*args, **kwargs)

    def test_seed_to_mnemonic_random(self):
        r_seed1 = SEED()
        r_seed2 = SEED()
        mnemonic1 = seed_to_mnemonic(r_seed1)
        mnemonic2 = seed_to_mnemonic(r_seed2)

        self.assertNotEqual(mnemonic1, S1_Mne)
        self.assertNotEqual(mnemonic2, S1_Mne)
        self.assertNotEqual(mnemonic1, mnemonic2)

    def test_seed_to_mnemonic_known(self):
        mnemonic = seed_to_mnemonic(S1)
        self.assertEqual(mnemonic, S1_Mne)

    def test_mnemonic_to_seed(self):
        seed = mnemonic_to_seed(S1_Mne)
        self.assertEqual( bin2hstr(seed), bin2hstr(S1))

    @pytest.mark.skip(reason="need to improve SWIG exception wrapping")
    def test_mnemonic_to_seed_invalid_word(self):
        bad_word_list = S1_Mne.replace('dragon', 'covfefe')
        with self.assertRaises(ValueError):
            mnemonic2bin(bad_word_list, wordlist)
