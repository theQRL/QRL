from binascii import hexlify
from collections import namedtuple

from qrl.core import config
from qrl.crypto.hmac_drbg import GEN, GEN_range
from qrl.crypto.misc import sha256

HashChainBundle = namedtuple('HashChainBundle', 'seed hashchain hc_terminator')


class HashChain(object):
    def __init__(self, xmss, blocks_per_epoch=config.dev.blocks_per_epoch):
        self._xmss = xmss
        self.blocks_per_epoch = blocks_per_epoch

    def _get_hc_seed(self, epoch):
        """

        :param epoch:
        :type epoch:
        :return:
        :rtype:
        """
        half = int(config.dev.blocks_per_epoch / 2)
        x = GEN(self._xmss._seed_private, half + epoch, l=32)
        y = GEN(x, half, l=32)
        z = GEN(y, half, l=32)
        z = hexlify(z)
        z = GEN_range(z, 1, config.dev.hashchain_nums)
        return z

    def _calc_hashchain(self, epoch):
        """
        generates a 20,000th hash in iterative sha256 chain..derived from private SEED
        :param epoch:
        :type epoch: int
        :return:
        """
        hc_seed = self._get_hc_seed(epoch)

        hc = []
        for hash_chain in hc_seed:
            hc.append([hash_chain])

        hc_terminator = []
        for hash_chain in hc[:-1]:  # skip last element as it is reveal hash
            for x in range(self.blocks_per_epoch):
                hash_chain.append(sha256(hash_chain[-1]))
            hc_terminator.append(hash_chain[-1])

        # Reveal hash chain
        for hash_chain in hc[-1:]:
            # Extra hash to reveal one hash value
            for x in range(self.blocks_per_epoch + 1):
                hash_chain.append(sha256(hash_chain[-1]))
            hc_terminator.append(hash_chain[-1])

        return hc_seed, hc, hc_terminator

    def hashchain(self, epoch=0):
        """

        :param epoch:
        :type epoch:
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.xmss import XMSS; isinstance(HashChain( XMSS(4, xmss_test_seed1) ).hashchain(), HashChainBundle)
        True
        """
        # type: (int) -> HashChainBundle
        return HashChainBundle(*self._calc_hashchain(epoch))

    def hashchain_reveal(self, epoch=0):
        """

        :param epoch:
        :type epoch:
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.xmss import XMSS; HashChain( XMSS(4, xmss_test_seed1) ).hashchain_reveal() == hashchain_reveal_expected1
        True
        """
        hc_seed, hc, hc_terminator = self._calc_hashchain(epoch)
        return hc_terminator
