from collections import namedtuple

from pyqrllib.pyqrllib import getHashChainSeed, sha2_256
from qrl.core import config

HashChainBundle = namedtuple('HashChainBundle', 'seed hashchain hc_terminator')


def _calc_hashchain(
        seed_private,
        epoch,
        blocks_per_epoch):
    """
    generates a 20,000th hash in iterative sha256 chain..derived from private SEED
    :param epoch:
    :type epoch: int
    :return:
    """
    hc_seed = getHashChainSeed(seed_private, epoch, 1)

    hc = [[bytes(hash_chain)] for hash_chain in hc_seed]

    hc_terminator = []

    # Reveal hash chain
    for hash_chain in hc[-1:]:
        # Extra hash to reveal one hash value
        for x in range(blocks_per_epoch):
            hash_chain.append(bytes(sha2_256(hash_chain[-1])))
        hc_terminator.append(hash_chain[-1])

    return hc_seed, hc, hc_terminator


def hashchain(seed_private,
              epoch=0,
              blocks_per_epoch=config.dev.blocks_per_epoch):
    # type: (bytes, int, int) -> HashChainBundle
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
    >>> binvec2hstr(hashchain_reveal(hashchain_reveal_input)) == hashchain_reveal_expected1
    True
    """
    tmp = hashchain(seed_private, epoch, blocks_per_epoch)
    return tmp.hc_terminator
