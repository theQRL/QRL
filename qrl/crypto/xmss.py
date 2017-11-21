# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from pyqrllib.pyqrllib import bin2hstr, getRandomSeed, str2bin, bin2mnemonic, mnemonic2bin, XmssFast  # noqa


class XMSS(object):
    # FIXME: Getters are only temporarily. Delete everything or use properties
    def __init__(self, tree_height, seed=None, _xmssfast=None):
        """
        :param
        tree_height: height of the tree to generate. number of OTS keypairs=2**tree_height
        :param seed:

        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1)._xmss.getHeight()
        4
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1)._xmss.getSecretKeySize()
        132
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1)._xmss.getSignatureSize()
        2308
        >>> from qrl.crypto.doctest_data import *; len(XMSS(4, xmss_test_seed1)._xmss.getSK()) == XMSS(4, xmss_test_seed1)._xmss.getSecretKeySize()
        True

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1)._xmss.getPK() )
        '26b3bcc104d686ecfd9fdea7b1963384339121430fbe056cab7c3048ea3e4c4e51ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1)._xmss.getSK() ) == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1)._xmss.getRoot() )
        '26b3bcc104d686ecfd9fdea7b1963384339121430fbe056cab7c3048ea3e4c4e'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1)._xmss.getPKSeed() )
        '51ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1)._xmss.getIndex()
        0
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1)._xmss.getSKSeed() )
        '5f2eb95ccf6a0e3e7f472c32d234340c20b3fd379dc28b710affcc0cb2afa57b'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1)._xmss.getSKPRF() )
        '3aa40c0f99459afe7efe72eb9517ee8ded49ccd51dab72ebf6bc37d73240bb3a'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1)._xmss.getAddress('Q')
        'Q1d651431536359202ce7095757e3ed66f579a6eab488ac1331486f207c91604016b6a443'

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2)._xmss.getPK() )         # doctest: +SKIP
        ''
        """

        self._type = 'XMSS'

        if _xmssfast is not None:
            self._xmss = _xmssfast
        else:
            # TODO: This is the old code, probably it should be removed

            if seed is None:
                # FIXME: Improve seed generation
                self._seed = getRandomSeed(48, '')
            else:
                if isinstance(seed, str):
                    self._seed = str2bin(seed)
                else:
                    self._seed = seed

            self._xmss = XmssFast(self._seed, tree_height)

        self.addresses = [(0, self.get_address(), self.get_number_signatures())]

    @property
    def height(self):
        return self._xmss.getHeight()

    def _sk(self):
        # FIXME: Move to property
        """
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(4, xmss_test_seed1)._sk()) == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(4, xmss_test_seed2)._sk()) == xmss_sk_expected2
        True
        """
        return bytes(self._xmss.getSK())

    def pk(self):
        # FIXME: Move to property
        """
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(4, xmss_test_seed1).pk()) == xmss_pk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(4, xmss_test_seed2).pk()) == xmss_pk_expected2
        True
        """
        return bytes(self._xmss.getPK())

    def get_number_signatures(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1).get_number_signatures()
        16
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_number_signatures()
        16
        """
        # type: () -> int
        return 2 ** self._xmss.getHeight()

    def get_remaining_signatures(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1).get_remaining_signatures()
        16
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_remaining_signatures()
        16
        """
        return self.get_number_signatures() - self._xmss.getIndex()

    def get_mnemonic(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; XMSS(4, hstr2bin(xmss_mnemonic_seed1)).get_mnemonic() == xmss_mnemonic_test1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(4, hstr2bin(xmss_mnemonic_seed2)).get_mnemonic() == xmss_mnemonic_test2
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(4, mnemonic2bin(xmss_mnemonic_test1)).get_mnemonic() == xmss_mnemonic_test1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(4, mnemonic2bin(xmss_mnemonic_test2)).get_mnemonic() == xmss_mnemonic_test2
        True
        """
        return bin2mnemonic(self._xmss.getSeed())

    def get_address(self):
        # FIXME: Move to property
        return self._xmss.getAddress('Q')

    def get_type(self):
        # FIXME: Move to property
        # type: () -> str
        return self._type

    def get_index(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1).get_index()
        0
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_index()
        0
        >>> from qrl.crypto.doctest_data import *
        >>> xmss = XMSS(4, xmss_test_seed2)
        >>> s = xmss.SIGN(str2bin("test"))
        >>> xmss.get_index()
        1
        """
        # type: () -> int
        return self._xmss.getIndex()

    def set_index(self, new_index):
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *
        >>> xmss = XMSS(4, xmss_test_seed1)
        >>> xmss.set_index(1)
        >>> xmss.get_index()
        1
        >>> from qrl.crypto.doctest_data import *
        >>> xmss = XMSS(4, xmss_test_seed1)
        >>> xmss.set_index(10)
        >>> xmss.get_index()
        10
        """
        self._xmss.setIndex(new_index)

    def get_hexseed(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed1).get_hexseed()
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_hexseed()
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return bin2hstr(self._seed)

    def get_seed(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1).get_seed() )
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2).get_seed() )
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return self._seed

    def get_seed_public(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1).get_seed_private() )
        '5f2eb95ccf6a0e3e7f472c32d234340c20b3fd379dc28b710affcc0cb2afa57b'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2).get_seed_private() )
        'ad70ef34f316aaadcbf16a64b1b381db731eb53d833745c0d3eaa1e24cf728a2'
        """
        return bytes(self._xmss.getPKSeed())

    def get_seed_private(self):
        # FIXME: Move to property
        """
        :return:
        :rtype:

        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed1).get_seed_public() )
        '51ec21420dd061739e4637fd74517a46f86f89e0fb83f2526fafafe356e564ff'
        >>> from qrl.crypto.doctest_data import *; bin2hstr( XMSS(4, xmss_test_seed2).get_seed_public() )
        'df2355c48096f2351e4d04db57b326c355345552d31b75a65ac18b1f6d7c7875'
        """
        return bytes(self._xmss.getSKSeed())

    @staticmethod
    # NOTE: USED EXTERNALLY!!!
    def VERIFY(message: bytes, signature: bytes, pk: bytes):
        """
        Verify an xmss sig with shorter PK
        same function but verifies using shorter signature where PK: {root, hex(_public_SEED)}
        # main verification function..
        :param pk:
        :type pk:
        :param message:
        :param signature:
        :return:

        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_message"), hstr2bin(xmss_sign_expected1), hstr2bin(xmss_pk_expected1))
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_messagex"), hstr2bin(xmss_sign_expected1), hstr2bin(xmss_pk_expected1))
        False
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_message"), hstr2bin(xmss_sign_expected2), hstr2bin(xmss_pk_expected2))
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY( str2bin("test_messagex"), hstr2bin(xmss_sign_expected2), hstr2bin(xmss_pk_expected2))
        False
        """
        return XmssFast.verify(message, signature, pk)

    def SIGN(self, message):
        # type: (bytes) -> bytes
        """
        :param message:
        :return:

        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(4, xmss_test_seed1).SIGN(str2bin("test_message"))) == xmss_sign_expected1
        True
        >>> from qrl.crypto.doctest_data import *; bin2hstr(XMSS(4, xmss_test_seed2).SIGN(str2bin("test_message"))) == xmss_sign_expected2
        True
        """
        return bytes(self._xmss.sign(message))

    def list_addresses(self):
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
