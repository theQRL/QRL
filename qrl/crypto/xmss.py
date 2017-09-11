# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import time
from _ctypes import Union
from binascii import hexlify, unhexlify
from math import ceil, log, floor

from qrl.core import logger
from qrl.crypto.hmac_drbg import new_keys, GEN_range
from qrl.crypto.misc import sha256
from qrl.crypto.mnemonic import seed_to_mnemonic

from pyqrllib.pyqrllib import Xmss, vec2hexstr
from pyqrllib.misc import get_seed


# creates XMSS trees with W-OTS+ using PRF (hmac_drbg)

class XMSS(object):
    """
    xmss python implementation
    An XMSS private key contains N = 2^h WOTS+ private keys, the leaf index idx of the next WOTS+ private key that has not yet been used
    and SK_PRF, an m-byte key for the PRF.
    The XMSS public key PK consists of the root of the binary hash tree and the bitmasks from xmss and l-tree.
    a class which creates an xmss wrapper. allows stateful signing from an xmss tree of signatures.
    """
    #FIXME: Getters are only temporarily. Delete everything or use properties

    def __init__(self, tree_height, SEED=None):
        # type: (int, Union[str, None]) -> None
        """
        :param
        tree_height: height of the tree to generate. number of OTS keypairs=2**tree_height
        :param SEED:
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test1)).get_address()
        'Q034125172e37499649efb2df6c2de8d70258c7e87b47d9b40fb866fe54c124ae5a17'
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(3, mnemonic_to_seed(xmss_mnemonic_test2)).get_address()
        'Qe09ca5ad5f566d55c3545dfebe3ee58f4976d6370e83f944212c6159ed1ce08c6891'
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test1)).get_mnemonic() == xmss_mnemonic_test1
        True
        >>> from qrl.crypto.doctest_data import *; from qrl.crypto.mnemonic import mnemonic_to_seed; XMSS(4, mnemonic_to_seed(xmss_mnemonic_test2)).get_mnemonic() == xmss_mnemonic_test2
        True

        # LEGACY TESTS
        >>> from qrl.crypto.doctest_data import *; hexlify(XMSS(3, xmss_test_seed1)._seed)
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; hexlify(XMSS(3, xmss_test_seed1)._seed_public)
        '83a91a4d7a560abd41ea95f412cde98eda03769d72b5755bb7c4ab7433e73530203fa670a4c6d4f2ad5ac0f8f0ce30a7'
        >>> from qrl.crypto.doctest_data import *; hexlify(XMSS(3, xmss_test_seed1)._seed_private)
        '32eee808dc7c5dfe26fd4859b415e5a713bd764036bbeefd7a541da9a1cc7b9fcaf17da039a62756b63835de1769e05e'

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
        'e2dd84011e409a79ad9e7fead9a455436e36838d966a73d5947b3710b36d625ae00b3f9d338de90488973787b0916a4a9ae8bebf4e2bc07a7bc18f1a62215182'

        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSK() )
        '00000000f5977c8283546a63723bc31d2619124f11db4658643336741df81757d5ad3062221e124311ec7f7181568de7938df805d894f5fded465001a04e260a49482cf5e00b3f9d338de90488973787b0916a4a9ae8bebf4e2bc07a7bc18f1a62215182e2dd84011e409a79ad9e7fead9a455436e36838d966a73d5947b3710b36d625a'

        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getRoot() )
        'e2dd84011e409a79ad9e7fead9a455436e36838d966a73d5947b3710b36d625a'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getPKSeed() )
        'e00b3f9d338de90488973787b0916a4a9ae8bebf4e2bc07a7bc18f1a62215182'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getIndex() )
        '00000000'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSKSeed() )
        'f5977c8283546a63723bc31d2619124f11db4658643336741df81757d5ad3062'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSKPRF() )
        '221e124311ec7f7181568de7938df805d894f5fded465001a04e260a49482cf5'
        >>> from qrl.crypto.doctest_data import *; vec2hexstr( XMSS(3, xmss_test_seed1)._xmss.getSKPRF() )
        '221e124311ec7f7181568de7938df805d894f5fded465001a04e260a49482cf5'
        """

        self._number_signatures = 2 ** tree_height

        # FIXME: no error handling for invalid seeds
        self._type = 'XMSS'
        self._index = 0

        # use supplied 48 byte SEED, else create randomly from os to generate private and public seeds..
        self._seed, self._seed_public, self._seed_private = new_keys(SEED)

        # TODO: #####################
        # FIXME
        self._new_seed, self._new_seed_public, self._new_seed_private = get_seed()
        self._xmss = Xmss(self._new_seed, tree_height)
        # TODO: #####################

        # create the tree
        self._tree, self._x_bms, self._l_bms, self._privs, self._pubs = self._xmss_tree(
            tree_height=tree_height,
            public_SEED=self._seed_public,
            private_SEED=self._seed_private)

        self.root = ''.join(self._tree[-1])
        self.PK = [self.root, self._x_bms, self._l_bms]
        self.PK_short = [self.root, hexlify(self._seed_public)]             # derived from SEED
        catPK_short = self.root + hexlify(self._seed_public)
        self.address = XMSS.create_address_from_key(catPK_short)

        # data to allow signing of smaller xmss trees/different addresses derived from same SEED..
        # position in wallet denoted by first number and address/tree by signatures
        self.addresses = [(0, self.address, self.get_number_signatures())]

    def _sk(self, i=None):
        # type: (int) -> List[str]
        """
        Return OTS private key at position i
        :param i:
        :return:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1)._sk() == xmss_sk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed2)._sk() == xmss_sk_expected2
        True
        """
        if i is None:
            i = self._index
        return self._privs[i]

    def pk(self, i=None):
        # type: (int) -> List[str]
        """
        Return OTS public key at position i
        :param i:
        :return:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).pk() == xmss_pk_expected1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed2).pk() == xmss_pk_expected2
        True
        """
        if i is None:
            i = self._index
        return self._pubs[i]

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
        # type: () -> int
        return self.get_number_signatures() - self._index

    def get_mnemonic(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_mnemonic() == xmss_mnemonic_expected1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed2).get_mnemonic() == xmss_mnemonic_expected2
        True
        """
        # type: () -> List[str]
        return seed_to_mnemonic(self._seed)

    def get_address(self):
        return self.address

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
        self._index = new_index

    def get_hexseed(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).get_hexseed()
        '303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030'
        >>> from qrl.crypto.doctest_data import *; XMSS(4, xmss_test_seed2).get_hexseed()
        '333133313331333133313331333133313331333133313331333133313331333133313331333133313331333133313331'
        """
        return hexlify(self._seed)

    def get_seed_private(self):
        """
        :return:
        :rtype:
        >>> from qrl.crypto.doctest_data import *; hexlify( XMSS(3, xmss_test_seed1).get_seed_private() )
        '32eee808dc7c5dfe26fd4859b415e5a713bd764036bbeefd7a541da9a1cc7b9fcaf17da039a62756b63835de1769e05e'
        >>> from qrl.crypto.doctest_data import *; hexlify( XMSS(4, xmss_test_seed2).get_seed_private() )
        '529647107c42786b576ac1cfd9b532de2f66d2a8374f1f6293e986009b940864ca80c295092d6217afddf5be0aeb9695'
        """
        return self._seed_private

    @staticmethod
    # NOTE: USED EXTERNALLY!!!
    def VERIFY(message, signature):
        # type: (bytearray, list) -> bool
        # NOTE: used by transaction
        """
        Verify an xmss sig with shorter PK
        same function but verifies using shorter signature where PK: {root, hex(_public_SEED)}
        # main verification function..
        :param message:
        :param signature:
        :return:
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY("test_message", xmss_sign_expected1)
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY("test_messagex", xmss_sign_expected1)
        False
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY("test_message", xmss_sign_expected2)
        True
        >>> from qrl.crypto.doctest_data import *; XMSS.VERIFY("test_messagex", xmss_sign_expected2)
        False
        """

        def verify_wpkey(signature, message, pub, w=16):
            l, s = XMSS.get_s(message, w)

            pub2 = []

            for x in range(int(l)):  # merkle.chain_fn(priv[0],pub[0][0],15,pub[0][1])
                # NOTE: Why is this using chain_fn2???
                pub2.append(XMSS.chain_fn2(signature[x], pub[0][0], s[x], pub[0][1]))

            if pub2 == pub[1:]:
                return True

            return False

        def _verify_auth(auth_route, i_bms, pub, PK):
            """
            verify an XMSS auth root path..requires the xmss authentication route,
            OTS public key and XMSS public key (containing merkle root, x and l bitmasks) and i
            regenerate leaf from pub[i] and l_bm, use auth route to navigate up
            merkle tree to regenerate the root and compare with PK[0]
            :param auth_route:
            :param i_bms:
            :param pub:
            :param PK:
            :return:
            """
            root = PK[0]
            x_bms = PK[1]
            l_bms = PK[2]

            leaf = XMSS._l_tree(pub, l_bms)

            h = len(auth_route)

            node = None
            for x in range(h - 1):  # last check is simply to confirm root = pair, no need for sha xor..
                if i_bms[x][0] == 'L':
                    node = sha256(hex(int(leaf, 16) ^ int(x_bms[i_bms[x][1]], 16))[2:-1] + hex(
                        int(auth_route[x], 16) ^ int(x_bms[i_bms[x][2]], 16))[2:-1])
                else:
                    node = sha256(hex(int(auth_route[x], 16) ^ int(x_bms[i_bms[x][0]], 16))[2:-1] + hex(
                        int(leaf, 16) ^ int(x_bms[i_bms[x][1]], 16))[2:-1])

                leaf = node

            if node == root:
                return True

            return False

        def _verify_auth_SEED(auth_route, i_bms, pub, PK_short):
            """
            same as verify_auth but using the shorter PK which is {root, hex(_public_SEED)} to reconstitute the long PK
            with bitmasks then call above..
            :param auth_route:
            :param i_bms:
            :param pub:
            :param PK_short:
            :return:
            """
            PK = []
            root = PK_short[0]
            public_SEED = unhexlify(PK_short[1])

            rand_keys = GEN_range(public_SEED, 1, 14 + i_bms[-1][-1] + 1,
                                  32)  # i_bms[-1][-1] is the last bitmask in the tree. +1 because it counts from 0.

            PK.append(root)
            PK.append(rand_keys[14:])  # _x_bms
            PK.append(rand_keys[:14])  # _l_bms

            return _verify_auth(auth_route, i_bms, pub, PK)

        if not verify_wpkey(signature[1], message, signature[4]):
            return False

        if not _verify_auth_SEED(signature[2], signature[3], signature[4], signature[5]):
            return False

        return True

    def SIGN(self, msg):
        # type: (bytearray) -> tuple
        """
        :param msg:
        :return:
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed1).SIGN("test_message") == xmss_sign_expected1
        True
        >>> from qrl.crypto.doctest_data import *; XMSS(3, xmss_test_seed2).SIGN("test_message") == xmss_sign_expected2
        True
        """

        def sign_wpkey(priv, message, pub, w=16):
            l, s = XMSS.get_s(message, w)

            signature = []

            for x in range(int(l)):
                signature.append(XMSS.chain_fn(priv[x], pub[0][0], s[x], pub[0][1]))

            return signature

        def _xmss_route(x_bms, x_tree, i=0):
            # type: (list, list, int) -> Union[tuple, None]
            """
            generate the xmss tree merkle auth route for a given ots key (starts at 0)
            :param x_bms:
            :param x_tree:
            :param i:
            :return:
            """
            auth_route = []
            i_bms = []
            nodehash_list = [item for sublist in x_tree for item in sublist]
            h = len(x_tree)
            leaf = x_tree[0][i]
            for x in range(h):

                if len(x_tree[x]) == 1:  # must be at root layer
                    if node == ''.join(x_tree[x]):
                        auth_route.append(''.join(x_tree[x]))
                    else:
                        logger.info('Failed..root')
                        return

                elif i == len(x_tree[x]) - 1 and leaf in x_tree[
                            x + 1]:  # for an odd node it goes up a level each time until it branches..
                    i = x_tree[x + 1].index(leaf)
                    n = nodehash_list.index(leaf)
                    nodehash_list[n] = None  # stops at first duplicate in list..need next so wipe..

                else:
                    n = nodehash_list.index(leaf)  # position in the list == bitmask..
                    if i % 2 == 0:  # left leaf, go right..
                        # logger.info((  'left'
                        node = sha256(hex(int(leaf, 16) ^ int(x_bms[n], 16))[2:-1] + hex(
                            int(nodehash_list[n + 1], 16) ^ int(x_bms[n + 1], 16))[2:-1])
                        pair = nodehash_list[n + 1]
                        auth_route.append(pair)
                        i_bms.append(('L', n, n + 1))

                    elif i % 2 == 1:  # right leaf go left..
                        node = sha256(hex(int(nodehash_list[n - 1], 16) ^ int(x_bms[n - 1], 16))[2:-1] + hex(
                            int(leaf, 16) ^ int(x_bms[n], 16))[2:-1])
                        pair = nodehash_list[n - 1]
                        auth_route.append(pair)
                        i_bms.append((n - 1, n))

                    try:
                        x_tree[x + 1].index(node)  # confirm node matches a hash in next layer up?
                    except:
                        logger.warning(('Failed at height', str(x)))
                        return
                    leaf = node
                    i = x_tree[x + 1].index(leaf)

            return auth_route, i_bms

        i = self._index

        # formal sign and increment the index to the next OTS to be used..
        logger.info('xmss signing with OTS n = %s', str(self._index))
        s = sign_wpkey(self._privs[i], msg, self._pubs[i])
        auth_route, i_bms = _xmss_route(self._x_bms, self._tree, i)
        self._index += 1

        return i, s, auth_route, i_bms, self.pk(i), self.PK_short

    @staticmethod
    # NOTE: USED EXTERNALLY!!!
    def create_address_from_key(key):
        # type: (str) -> str
        sha_r1 = sha256(key)
        sha_r2 = sha256(sha_r1)
        return 'Q' + sha_r1 + sha_r2[:4]

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

    @staticmethod
    def fn_k(x, k):
        return sha256(k + x)

    @staticmethod
    def chain_fn(x, r, i, k):
        if i == 0:
            return x
        for y in range(i):
            x = XMSS.fn_k(hex(int(x, 16) ^ int(r[y], 16))[2:-1], k)
        return x

    @staticmethod
    def chain_fn2(x, r, i, k):
        for y in range(i, 15):
            x = XMSS.fn_k(hex(int(x, 16) ^ int(r[y], 16))[2:-1], k)
        return x

    @staticmethod
    def _xmss_tree(tree_height, private_SEED, public_SEED):
        # type: (int, str, str) -> List[list, List[str], list, list, list]
        # FIXME: Most other methods use pub/priv. Refactor?
        # no.leaves = 2^h

        def _xmss_random_wpkey(seed, w=16, verbose=False):
            # type: (bytearray, int, bool) -> tuple
            """
            first calculate l_1 + l_2 = l .. see whitepaper http://theqrl.org/whitepaper/QRL_whitepaper.pdf
            if using SHA-256 then m and n = 256
            :param seed:
            :param w:
            :param verbose:
            :return:
            """
            start_time = time.time()
            l, l_1, l_2 = XMSS.get_lengths(w)

            pub = []

            # first create l+w-1 256 bit secret key fragments from PRF seed (derived from PRF on private_SEED)
            # l n-bits will be private key, remaining w-1 will be r, the randomisation elements for the chaining function
            # finally generate k the key for the chaining function..

            sk = GEN_range(seed, 1, l + w - 1 + 1, 32)

            priv = sk[:l]
            r = sk[l:l + w - 1]
            k = sk[-1]

            pub.append((r, k))  # pk_0 = (r,k) ..where r is a list of w-1 randomisation elements

            for sk_ in priv:
                pub.append(XMSS.chain_fn(sk_, r, w - 1, k))

            if verbose:
                logger.info(str(time.time() - start_time))

            return priv, pub

        number_signatures = 2 ** tree_height

        # generate the OTS keys, bitmasks and l_trees randomly (change to SEED+KEY PRF)

        leafs = []
        pubs = []
        privs = []

        # for random key generation: public_SEED: 14 = l_bm, 2n-2 - 2n+h = x_bm (see comment below)

        rand_keys = GEN_range(public_SEED, 1, 14 + 2 * number_signatures + int(tree_height), 32)

        l_bms = rand_keys[:14]
        x_bms = rand_keys[14:]

        # generate n hexlified private key seeds from PRF

        sk_keys = GEN_range(private_SEED, 1, number_signatures, 32)

        for x in range(number_signatures):
            priv, pub = _xmss_random_wpkey(seed=sk_keys[x])
            leaf = XMSS._l_tree(pub, l_bms)
            leafs.append(leaf)
            pubs.append(pub)
            privs.append(priv)

        # create xmss tree with 2^n leaves, need 2 bitmasks per parent node (excluding layer 0), therefore for a perfect binary tree total nodes = 2*n_leaves-1
        # Given even an odd number we just create a bm for each node but dont use it for ease (the extra moves up to just below root) n_bm = 2*n-2 - 2n+h

        xmss_array = [leafs]

        p = 0
        for x in range(int(tree_height)):
            next_layer = []
            i = len(xmss_array[x]) % 2 + len(xmss_array[x]) / 2
            z = 0
            for y in range(i):
                if len(xmss_array[
                           x]) == z + 1:  # only one left, therefore odd leaf, just add to next layer until below the root
                    next_layer.append(xmss_array[x][z])
                    p += 1
                else:
                    next_layer.append(sha256(hex(int(xmss_array[x][z], 16) ^ int(x_bms[p], 16))[2:-1] + hex(
                        int(xmss_array[x][z + 1], 16) ^ int(x_bms[p + 1], 16))[2:-1]))
                    p += 2
                z += 2
            xmss_array.append(next_layer)

        return xmss_array, x_bms, l_bms, privs, pubs

    @staticmethod
    def _l_tree(pub, bm, l=67):
        if l == 67:
            j = 7
        else:
            j = ceil(log(l, 2))

        l_array = [pub[1:]]  # pk_0 = (r,k) - given with the OTS pk but not in the xmss tree..

        for x in range(j):
            next_layer = []
            i = len(l_array[x]) % 2 + len(l_array[x]) / 2
            z = 0
            for y in range(i):
                if len(l_array[x]) == z + 1:
                    next_layer.append(l_array[x][z])
                else:
                    # logger.info((  str(l_array[x][z])
                    next_layer.append(sha256(hex(int(l_array[x][z], 16) ^ int(bm[2 * x], 16))[2:-1] + hex(
                        int(l_array[x][z + 1], 16) ^ int(bm[2 * x + 1], 16))[2:-1]))
                z += 2
            l_array.append(next_layer)
        return ''.join(l_array[-1])

    @staticmethod
    def get_lengths(w):
        # TODO: describe the meaning of these values
        m = 256
        if w == 16:
            l_1 = 64
            l_2 = 3
        else:
            l_1 = ceil(m / log(w, 2))
            l_2 = floor(log((l_1 * (w - 1)), 2) / log(w, 2)) + 1
        l = int(l_1 + l_2)
        return l, l_1, l_2

    @staticmethod
    def get_s(message, w):
        l, l_1, l_2 = XMSS.get_lengths(w)
        message = sha256(message)  # outputs 256 bit -> 64 hexadecimals. each hex digit is therefore 4 bits..
        s = []
        checksum = 0
        for x in range(int(l_1)):
            y = int(message[x], 16)
            s.append(y)
            checksum += w - 1 - y
        c = (hex(checksum))[2:]
        if len(c) < 3:
            c = '0' + c
        for x in range(int(l_2)):
            y = int(c[x], 16)
            s.append(y)
        return l, s


if __name__ == "__main__":
    import doctest

    doctest.testmod()
