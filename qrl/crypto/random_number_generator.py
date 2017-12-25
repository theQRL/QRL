# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import random


class RNG(object):

    @staticmethod
    def generate(prf_seed: bytes, seq: int) -> bytes:
        random.seed(int(prf_seed))
        for i in range(seq):
            prf = random.random()

        return str(prf).encode()
