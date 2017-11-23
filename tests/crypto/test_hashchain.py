# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from pyqrllib.pyqrllib import bin2hstr

from qrl.core import logger
from qrl.crypto.hashchain import hashchain, hashchain_reveal
from qrl.crypto.misc import sha256, sha256_n

logger.initialize_default(force_console_output=True)


class TestHashChain(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHashChain, self).__init__(*args, **kwargs)

    def test_create_hashchain(self):
        seed = sha256(b'test_seed')

        HASHCHAIN_SIZE = 100
        hcb = hashchain(seed, 1, HASHCHAIN_SIZE)
        self.assertIsNotNone(hcb)
        self.assertEqual(HASHCHAIN_SIZE + 1, len(hcb.hashchain))

        # FIXME: Why seed comes as an array of tuples?
        self.assertEqual('127f5db0388cd82bd4af80b88e8d68409e1f70fd322f96b3f2aca55b0ade116f',
                         bin2hstr(hcb.seed[0]))

        self.assertEqual('1d3b37dedc74980941b3b65640e8d2851658feac0d38196f372ada9c2ac0b077',
                         bin2hstr(hcb.hc_terminator))
        self.assertEqual('1d3b37dedc74980941b3b65640e8d2851658feac0d38196f372ada9c2ac0b077',
                         bin2hstr(hcb.hashchain[-1]))
        self.assertEqual('127f5db0388cd82bd4af80b88e8d68409e1f70fd322f96b3f2aca55b0ade116f',
                         bin2hstr(hcb.hashchain[0]))
        self.assertNotEqual('127f5db0388cd82bd4af80b88e8d68409e1f70fd322f96b3f2aca55b0ade116f',
                            bin2hstr(hcb.hashchain[1]))
        self.assertEqual('ff7f4850bc6499e08e104c6967ee66e665e57d7e0e429072e646d14e1b92600a',
                         bin2hstr(hcb.hashchain[50]))

    def test_hashchain_reveal(self):
        seed = sha256(b'test_seed')

        self.assertEqual('1d3b37dedc74980941b3b65640e8d2851658feac0d38196f372ada9c2ac0b077',
                         bin2hstr(hashchain_reveal(seed, 1, 100)))
        self.assertEqual('127f5db0388cd82bd4af80b88e8d68409e1f70fd322f96b3f2aca55b0ade116f',
                         bin2hstr(hashchain_reveal(seed, 1, 0)))
        self.assertEqual('ff7f4850bc6499e08e104c6967ee66e665e57d7e0e429072e646d14e1b92600a',
                         bin2hstr(hashchain_reveal(seed, 1, 50)))
        self.assertNotEqual('ff7f4850bc6499e08e104c6967ee66e665e57d7e0e429072e646d14e1b92600a',
                            bin2hstr(hashchain_reveal(seed, 1, 51)))

    def test_hashchain_verify(self):
        seed = sha256(b'test_seed')

        HASHCHAIN_SIZE = 100
        hcb = hashchain(seed, 1, HASHCHAIN_SIZE)
        self.assertIsNotNone(hcb)
        self.assertEqual(HASHCHAIN_SIZE + 1, len(hcb.hashchain))

        for i, value in enumerate(hcb.hashchain):
            tmp = sha256_n(value, HASHCHAIN_SIZE - i)
            print("{:-4} {} {}".format(i, bin2hstr(value), bin2hstr(tmp)))
            self.assertEqual(hcb.hc_terminator, tmp)
