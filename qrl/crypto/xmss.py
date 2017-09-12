# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from binascii import unhexlify

from pyqrllib.pyqrllib import Xmss, vec2hexstr, getAddress, ucharVector, verify, tobin
from qrl.core import config
from qrl.crypto.mnemonic import seed_to_mnemonic

class XMSS(object):
    """
    xmss python implementation
    An XMSS private key contains N = 2^h WOTS+ private keys, the leaf index idx of the next WOTS+ private key that has not yet been used
    and SK_PRF, an m-byte key for the PRF.
    The XMSS public key PK consists of the root of the binary hash tree and the bitmasks from xmss and l-tree.
    a class which creates an xmss wrapper. allows stateful signing from an xmss tree of signatures.
    """

    # FIXME: Getters are only temporarily. Delete everything or use properties

    def __init__(self, tree_height, SEED=None):
        """
        :param
        tree_height: height of the tree to generate. number of OTS keypairs=2**tree_height
        :param SEED:
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test1)).get_address()
        'Qf3cd854ea42bb613dd6c1b28408a397fd8e20a7c5a2a311088aa581fda7eb8d110ce9226'
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test2)).get_address()
        'Qcda209053d03178e763590b1f42ed123954d2cc0832e698c6b13b4d95ecbc2de5f2352fe'
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(3, mnemonic_to_seed(xmss_mnemonic_test2)).get_address()
        'Q1c5cc669b6f7d0d7b82c6619242c16618eb7c91de44626ee7100afea266ffc9c20269ae8'

        # LEGACY TESTS
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed1).get_seed())
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed1).get_seed_public())
        '26751be66abe68ae69f959dd40ea3640c448628153d6eea5dd4f14e1ffb01425'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed1).get_seed_private())
        'f8ac70df871851eb09b1096e0f2ef9a07ebb26895ab866ed238db0f42b1438a5'

        # NEW TESTS
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getHeight()
        3
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getSecretKeySize()
        132
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getSignatureSize()
        2276
        >>> from qrl.crypto.doctest_data import *; len(XMSS(3, xmss_test_seed1)._xmss.getSK()) == XMSS(3, xmss_test_seed1)._xmss.getSecretKeySize()
        True

        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getPK() )
        '949eaea640537fe3e01fc007119815a55b6e94c7b342fac1ddbbe5698f439ca226751be66abe68ae69f959dd40ea3640c448628153d6eea5dd4f14e1ffb01425'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSK() ) == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getRoot() )
        '949eaea640537fe3e01fc007119815a55b6e94c7b342fac1ddbbe5698f439ca2'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getPKSeed() )
        '26751be66abe68ae69f959dd40ea3640c448628153d6eea5dd4f14e1ffb01425'
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getIndex()
        0
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSKSeed() )
        'f8ac70df871851eb09b1096e0f2ef9a07ebb26895ab866ed238db0f42b1438a5'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSKPRF() )
        'cc8e4fb060095f8366fa6de93ee8a0289d78c23db8afc121725898eb773e5dba'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSKPRF() )
        'cc8e4fb060095f8366fa6de93ee8a0289d78c23db8afc121725898eb773e5dba'
        >>> from qrl.crypto.doctest_data import *; getAddress('Q', XMSS(3, xmss_test_seed1)._xmss)
        'Qcb5ff6e654a98e8d95699597bc4eeb3e53338efa3b9e29a7d4e0a17f54e150b6581bbff8'

        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed2)._xmss.getPK() )         # doctest: +SKIP
        ''
        """
        self._number_signatures = 2 ** tree_height

        # FIXME: no error handling for invalid seeds
        self._type = 'XMSS'
        self._index = 0

        if SEED is None:
            raise Exception("Empty seed not supported")

        # TODO: #####################
        # FIXME Seed is fixed!!!!!!!!!!!!!!!!!!!!
        self._seed = ucharVector(len(SEED), 0)
        for i, c in enumerate(SEED):
            self._seed[i] = ord(c)
        self._xmss = Xmss(self._seed, tree_height)

        # TODO: Need to set an index

        # data to allow signing of smaller xmss trees/different addresses derived from same SEED..
        # position in wallet denoted by first number and address/tree by signatures
        self.addresses = [(0, self.get_address(), self.get_number_signatures())]

    def _sk(self):
        """
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed1)._sk()) == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed2)._sk()) == xmss_sk_expected2
        True
        """
        return self._xmss.getSK()

    def pk(self, i=None):
        """
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed1).pk()) == xmss_pk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed2).pk()) == xmss_pk_expected2
        True
        """
        return self._xmss.getPK()

    def get_number_signatures(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_number_signatures()
        8
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_number_signatures()
        16
        """
        # type: () -> int
        return self._number_signatures

    def get_remaining_signatures(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_remaining_signatures()
        8
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_remaining_signatures()
        16
        """
        return self.get_number_signatures() - self._xmss.getIndex()

    def get_mnemonic(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_mnemonic() == xmss_mnemonic_expected1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed2).get_mnemonic() == xmss_mnemonic_expected2
        True
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test1)).get_mnemonic() == xmss_mnemonic_test1
        True
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test2)).get_mnemonic() == xmss_mnemonic_test2
        True
        """
        # type: () -> List[str]
        return seed_to_mnemonic(self._seed)

    def get_address(self):
        return getAddress('Q', self._xmss)

    def get_type(self):
        # type: () -> str
        return self._type

    def get_index(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_index()
        0
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_index()
        0
        """
        # type: () -> int
        return self._index

    def set_index(self, new_index):
        raise NotImplementedError()

    def get_hexseed(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_hexseed()
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_hexseed()
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return vec2hexstr(self._seed)

    def get_seed(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1).get_seed() )
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(4, xmss_test_seed2).get_seed() )
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return self._seed

    def get_seed_public(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1).get_seed_private() )
        'f8ac70df871851eb09b1096e0f2ef9a07ebb26895ab866ed238db0f42b1438a5'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(4, xmss_test_seed2).get_seed_private() )
        'd901c63fe5c2e4c1b1f1186a962a35467b0b794fef7ae5692f0030604420e49b'
        """
        return self._xmss.getPKSeed()

    def get_seed_private(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1).get_seed_public() )
        '26751be66abe68ae69f959dd40ea3640c448628153d6eea5dd4f14e1ffb01425'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(4, xmss_test_seed2).get_seed_public() )
        '24ac443e4af9dc36a6cee1cd2dead818f88b1350fb97a4d8b5b8b7522dbe66b5'
        """
        return self._xmss.getSKSeed()

    @staticmethod
    # NOTE: USED EXTERNALLY!!!
    def VERIFY(message, signature, pk, height = config.dev):
        # type: (bytearray, list) -> bool
        # NOTE: used by transaction
        """
        Verify an xmss sig with shorter PK
        same function but verifies using shorter signature where PK: {root, hex(_public_SEED)}
        # main verification function..
        :param message:
        :param signature:
        :return:
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( tobin("test_message"), tobin(unhexlify(xmss_sign_expected1)), tobin(unhexlify(xmss_pk_expected1)), xmss_sign_expected1_h)
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( tobin("test_messagex"), tobin(unhexlify(xmss_sign_expected1)), tobin(unhexlify(xmss_pk_expected1)), xmss_sign_expected1_h)
        False
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( tobin("test_message"), tobin(unhexlify(xmss_sign_expected2)), tobin(unhexlify(xmss_pk_expected2)), xmss_sign_expected2_h)
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( tobin("test_messagex"), tobin(unhexlify(xmss_sign_expected2)), tobin(unhexlify(xmss_pk_expected2)), xmss_sign_expected2_h)
        False
        """

        return verify(message, signature, pk, height)

    def SIGN(self, message):
        # type: (bytearray) -> tuple
        """
        :param message:
        :return:
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed1).SIGN(tobin("test_message"))) == xmss_sign_expected1
        True
        >>> from qrl.crypto.doctest_data import *; vec2hexstr(XMSS(3, xmss_test_seed2).SIGN(tobin("test_message"))) == xmss_sign_expected2
        True
        """
        return self._xmss.sign(message)

    @staticmethod
    # NOTE: USED EXTERNALLY!!!
    def create_address_from_key(key):
        return getAddress('Q', key)

    # NOTE: USED EXTERNALLY!!!
    def list_addresses(self):
        # FIXME: Probably not used and obsolete
        """
        List the addresses derived in the main tree
        :return:
        """
        addr_arr = []
        for addr in self.addresses:
            addr_arr.append(addr[1])

        return addr_arr


if __name__ == "__main__":
    import doctest

    doctest.testmod()
