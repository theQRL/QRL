# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core import logger
from qrl.crypto.hmac_drbg import SEED
from qrl.crypto.mnemonic import seed_to_mnemonic, mnemonic_to_seed
from tests.crypto.known_values import S1, S1_Mne

logger.initialize_default(force_console_output=True)


# FIXME: These values test consistency. There is no golden value or second implementation to compare with.

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
        self.assertEqual(seed, S1)
