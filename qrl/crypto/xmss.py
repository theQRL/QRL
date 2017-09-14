# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from pyqrllib.pyqrllib import Xmss, bin2hstr, getRandomSeed, str2bin, bin2mnemonic, mnemonic2bin, hstr2bin
from qrl.core import config
from qrl.crypto.words import wordlist


class XMSS(object):
    """
    xmss python implementation
    An XMSS private key contains N = 2^h WOTS+ private keys, the leaf index idx of the next WOTS+ private key that has not yet been used
    and SK_PRF, an m-byte key for the PRF.
    The XMSS public key PK consists of the root of the binary hash tree and the bitmasks from xmss and l-tree.
    a class which creates an xmss wrapper. allows stateful signing from an xmss tree of signatures.
    """

    # FIXME: Getters are only temporarily. Delete everything or use properties

    def __init__(self, tree_height, seed=None):
        """
        :param
        tree_height: height of the tree to generate. number of OTS keypairs=2**tree_height
        :param seed:
        >>> from qrl.crypto.doctest_data import *; XMSS(4, mnemonic2bin(xmss_mnemonic_test1, wordlist)).get_address()
        'Q572721d2221f1d43b18eecacb945221f1156f1e2f519b71e3def43d761e88f3af72feb52'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, mnemonic2bin(xmss_mnemonic_test2, wordlist)).get_address()
        'Q578230464f0550df33f1bad86b725ce6e6c5e278c5d03a100fb93c1d282daec21b2422f2'
        >>> from qrl.crypto.doctest_data import *; XMSS(3, mnemonic2bin(xmss_mnemonic_test2, wordlist)).get_address()
        'Q40cc0f0d0e821b958aec4416dbeb1243b9eab7c18b3a789f20a7f3cd328b4d4cb5f26109'

        # LEGACY TESTS
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed1).get_seed())
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed1).get_seed_public())
        '51ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed1).get_seed_private())
        '5f2eb95ccf6a0e3e7f472c32d234340c20b3fd379dc28b710affcc0cb2afa57b'

        # NEW TESTS
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getHeight()
        3
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getSecretKeySize()
        132
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getSignatureSize()
        2276
        >>> from qrl.crypto.doctest_data import *; len(XMSS(3, xmss_test_seed1)._xmss.getSK()) == XMSS(3, xmss_test_seed1)._xmss.getSecretKeySize()
        True

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1)._xmss.getPK() )
        '10ad36acb053f22494767e64edbfeb4202131fe791bcc3fe6d353777ff4b742351ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1)._xmss.getSK() ) == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1)._xmss.getRoot() )
        '10ad36acb053f22494767e64edbfeb4202131fe791bcc3fe6d353777ff4b7423'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1)._xmss.getPKSeed() )
        '51ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getIndex()
        0
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1)._xmss.getSKSeed() )
        '5f2eb95ccf6a0e3e7f472c32d234340c20b3fd379dc28b710affcc0cb2afa57b'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1)._xmss.getSKPRF() )
        '3aa40c0f99459afe7efe72eb9517ee8ded49ccd51dab72ebf6bc37d73240bb3a'
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._xmss.getAddress('Q')
        'Q535aa98bd64b7a54f0efaa14ba540accf12c84b7385338e586bd32c19590a0f748358240'

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed2)._xmss.getPK() )         # doctest: +SKIP
        ''
        """
        self._number_signatures = 2 ** tree_height

        self._type = 'XMSS'

        # FIXME: Set index to appropiate value after restoring
        self._index = 0

        if seed is None:
            # FIXME: Improve seed generation
            self._seed = getRandomSeed(48, '')
        else:
            if isinstance(seed, str):
                self._seed = str2bin(seed)
            else:
                self._seed = seed

        # TODO: #####################
        # FIXME Seed is fixed!!!!!!!!!!!!!!!!!!!!
        self._xmss = Xmss(self._seed, tree_height)

        # TODO: Need to set an index

        # data to allow signing of smaller xmss trees/different addresses derived from same SEED..
        # position in wallet denoted by first number and address/tree by signatures
        self.addresses = [(0, self.get_address(), self.get_number_signatures())]

    def _sk(self):
        """
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed1)._sk()) == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed2)._sk()) == xmss_sk_expected2
        True
        """
        return self._xmss.getSK()

    def pk(self, i=None):
        """
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed1).pk()) == xmss_pk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed2).pk()) == xmss_pk_expected2
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
        >>> from qrl.crypto.doctest_data import *; XMSS(4, mnemonic2bin(xmss_mnemonic_test1, wordlist)).get_mnemonic() == xmss_mnemonic_test1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(4, mnemonic2bin(xmss_mnemonic_test2, wordlist)).get_mnemonic() == xmss_mnemonic_test2
        True
        """
        # type: () -> List[str]
        return bin2mnemonic(self._seed, wordlist)

    def get_address(self):
        return self._xmss.getAddress('Q')

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
        return self._xmss.getIndex()

    def set_index(self, new_index):
        self._xmss.setIndex(new_index)

    def get_hexseed(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_hexseed()
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_hexseed()
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return bin2hstr(self._seed)

    def get_seed(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1).get_seed() )
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2).get_seed() )
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return self._seed

    def get_seed_public(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1).get_seed_private() )
        '5f2eb95ccf6a0e3e7f472c32d234340c20b3fd379dc28b710affcc0cb2afa57b'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2).get_seed_private() )
        'ad70ef34f316aaadcbf16a64b1b381db731eb53d833745c0d3eaa1e24cf728a2'
        """
        return self._xmss.getPKSeed()

    def get_seed_private(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(3, xmss_test_seed1).get_seed_public() )
        '51ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2).get_seed_public() )
        'df2355c48096f2351e4d04db57b326c355345552d31b75a65ac18b1f6d7c7875'
        """
        return self._xmss.getSKSeed()

    @staticmethod
    # NOTE: USED EXTERNALLY!!!
    def VERIFY(message, signature, pk, height=config.dev):
        # type: (bytearray, list) -> bool
        # NOTE: used by transaction
        """
        Verify an xmss sig with shorter PK
        same function but verifies using shorter signature where PK: {root, hex(_public_SEED)}
        # main verification function..
        :param message:
        :param signature:
        :return:
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_message"), hstr2bin(xmss_sign_expected1), hstr2bin(xmss_pk_expected1), xmss_sign_expected1_h)
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_messagex"), hstr2bin(xmss_sign_expected1), hstr2bin(xmss_pk_expected1), xmss_sign_expected1_h)
        False
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_message"), hstr2bin(xmss_sign_expected2), hstr2bin(xmss_pk_expected2), xmss_sign_expected2_h)
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_messagex"), hstr2bin(xmss_sign_expected2), hstr2bin(xmss_pk_expected2), xmss_sign_expected2_h)
        False
        """
        return Xmss.verify(message, signature, pk, height)

    def SIGN(self, message):
        # type: (bytearray) -> tuple
        """
        :param message:
        :return:
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed1).SIGN(str2bin("test_message"))) == xmss_sign_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(3, xmss_test_seed2).SIGN(str2bin("test_message"))) == xmss_sign_expected2
        True
        """
        return self._xmss.sign(message)

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
