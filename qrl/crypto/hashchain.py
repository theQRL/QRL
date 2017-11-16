from collections import namedtuple

from pyqrllib.pyqrllib import getHashChainSeed

from qrl.core import config
from qrl.crypto.misc import sha256, sha256_n

HashChainBundle = namedtuple('HashChainBundle', 'seed hashchain hc_terminator')


# FIXME: Move to C++

def _calc_hashchain(
        seed_private: bytes,
        epoch: int,
        blocks_per_epoch: int):
    # FIXME: Move to C++
    hc_seed = getHashChainSeed(seed_private, epoch, 1)

    hc = [bytes(hc_seed[0])]

    for x in range(blocks_per_epoch):
        hc.append(sha256(hc[-1]))

    hc_terminator = hc[-1]

    return hc_seed, hc, hc_terminator


def hashchain(seed_private: bytes,
              epoch: int = 0,
              blocks_per_epoch: int = config.dev.blocks_per_epoch) -> HashChainBundle:
    """
    >>> from qrl.crypto.doctest_data import *; isinstance(hashchain(hashchain_reveal_input), HashChainBundle)
    True
    """
    return HashChainBundle(*_calc_hashchain(seed_private, epoch, blocks_per_epoch))


def hashchain_reveal(seed_private,
                     epoch=0,
                     blocks_per_epoch=config.dev.blocks_per_epoch):
    """
    >>> from qrl.crypto.doctest_data import *
    >>> bin2hstr(hashchain_reveal(hashchain_reveal_input)) == hashchain_reveal_expected1
    True
    """
    hc_seed = getHashChainSeed(seed_private, epoch, 1)
    return sha256_n(hc_seed[0], blocks_per_epoch)
