from binascii import hexlify, unhexlify
from math import ceil, log

import time

from qrl.core import logger, config
from qrl.crypto.hmac_drbg import new_keys, GEN, GEN_range
from qrl.crypto.misc import sha256, sign_wpkey, verify_wpkey, get_lengths, chain_fn
from qrl.crypto.mnemonic import seed_to_mnemonic


# creates XMSS trees with W-OTS+ using PRF (hmac_drbg)


class XMSS(object):
    NUMBER_SIGNATURES = 8000

    """
    xmss python implementation
    An XMSS private key contains N = 2^h WOTS+ private keys, the leaf index idx of the next WOTS+ private key that has not yet been used
    and SK_PRF, an m-byte key for the PRF.
    The XMSS public key PK consists of the root of the binary hash tree and the bitmasks from xmss and l-tree.
    a class which creates an xmss wrapper. allows stateful signing from an xmss tree of signatures.
    """

    def __init__(self, signatures, SEED=None):
        # FIXME: no error handling for invalid seeds

        self.type = 'XMSS'
        self.index = 0

        if signatures > XMSS.NUMBER_SIGNATURES:
            signatures = XMSS.NUMBER_SIGNATURES

        # number of OTS keypairs in tree to generate: n=512 2.7s, n=1024 5.6s, n=2048 11.3s, n=4096 22.1s, n=8192 44.4s, n=16384 89.2s
        self.signatures = signatures
        self.remaining = signatures

        # use supplied 48 byte SEED, else create randomly from os to generate private and public seeds..
        self.SEED, self.public_SEED, self.private_SEED = new_keys(SEED)
        self.hexpublic_SEED = hexlify(self.public_SEED)
        self.hexprivate_SEED = hexlify(self.private_SEED)

        # create the mnemonic..
        self.seed_hexstring = hexlify(self.SEED)
        # FIXME: no error handling for invalid seeds
        self.mnemonic = seed_to_mnemonic(self.SEED)

        # create the tree
        self.tree, self.x_bms, self.l_bms, self.privs, self.pubs = self._xmss_tree(n=signatures,
                                                                                   private_SEED=self.private_SEED,
                                                                                   public_SEED=self.public_SEED)
        self.root = ''.join(self.tree[-1])

        self.PK = [self.root, self.x_bms, self.l_bms]
        self.catPK = [''.join(self.root), ''.join(self.x_bms), ''.join(self.l_bms)]
        self.address_long = 'Q' + sha256(''.join(self.catPK)) + sha256(sha256(''.join(self.catPK)))[:4]

        # derived from SEED
        self.PK_short = [self.root, hexlify(self.public_SEED)]
        self.catPK_short = self.root + hexlify(self.public_SEED)
        self.address = 'Q' + sha256(self.catPK_short) + sha256(sha256(self.catPK_short))[:4]

        # data to allow signing of smaller xmss trees/different addresses derived from same SEED..
        self.addresses = [(0,
                           self.address,
                           self.signatures)]  # position in wallet denoted by first number and address/tree by signatures

        self.subtrees = [(0,
                          self.signatures,
                          self.tree,
                          self.x_bms,
                          self.PK_short)]  # optimise by only storing length of x_bms..[:x]

        # create hash chain for POS
        self.hashchain()

    def index(self):
        """
        Returns next OTS key index to sign with
        :return:
        """
        return self.index

    def set_index(self, i):
        """
        Set the index
        :param i:
        :return:
        """
        self.index = i

    def sk(self, i=None):
        """
        Return OTS private key at position i
        :param i:
        :return:
        """
        if i is None:
            i = self.index
        return self.privs[i]

    def pk(self, i=None):
        """
        Return OTS public key at position i
        :param i:
        :return:
        """
        if i is None:
            i = self.index
        return self.pubs[i]

    def auth_route(self, i=0):
        """
        Calculate auth route for keypair i
        :param i:
        :return:
        """
        return self._xmss_route(self.x_bms, self.tree, i)

    def verify_auth(self, auth_route, i_bms, i=0):
        """
        Verify auth route using pk's
        :param auth_route:
        :param i_bms:
        :param i:
        :return:
        """
        return self._verify_auth(auth_route, i_bms, self.pk(i), self.PK)

    def verify_auth_SEED(self, auth_route, i_bms, i=0):
        """
        Verify auth route using ots pk and shorter PK {root, public_SEED}
        :param auth_route:
        :param i_bms:
        :param i:
        :return:
        """
        return self._verify_auth_SEED(auth_route, i_bms, self.pk(i), self.PK_short)

    def sign(self, msg, i=0):
        """
        Sign with OTS private key at position i
        :param msg:
        :param i:
        :return:
        """
        return sign_wpkey(self.privs[i], msg, self.pubs[i])

    def verify(self, msg, signature, i=0):
        """
        Verify OTS signature
        :param msg:
        :param signature:
        :param i:
        :return:
        """
        return verify_wpkey(signature, msg, self.pubs[i])

    def SIGN_long(self, msg, i=0):
        s = self.sign(msg, i)
        auth_route, i_bms = XMSS._xmss_route(self.x_bms, self.tree, i)
        return i, s, auth_route, i_bms, self.pk(i), self.PK  # SIG

    def SIGN_short(self, msg, i=0):
        s = self.sign(msg, i)
        auth_route, i_bms = XMSS._xmss_route(self.x_bms, self.tree, i)
        return i, s, auth_route, i_bms, self.pk(i), self.PK_short  # shorter SIG due to SEED rather than bitmasks

    def SIGN(self, msg):
        i = self.index

        # formal sign and increment the index to the next OTS to be used..
        logger.info('xmss signing with OTS n = %s', str(self.index))
        s = self.sign(msg, i)
        auth_route, i_bms = XMSS._xmss_route(self.x_bms, self.tree, i)
        self.index += 1
        self.remaining -= 1

        return i, s, auth_route, i_bms, self.pk(i), self.PK_short

    @staticmethod
    def VERIFY_long(msg, SIG):
        """
        verify an XMSS signature: {i, s, auth_route, i_bms, pk(i), PK(root, x_bms, l_bms)}
        SIG is a list composed of: i, s, auth_route, i_bms, pk[i], PK
        :param msg:
        :param SIG:
        :return:
        """
        if not verify_wpkey(SIG[1], msg, SIG[4]):
            return False

        if not XMSS._verify_auth(SIG[2], SIG[3], SIG[4], SIG[5]):
            return False

        return True

    @staticmethod
    def VERIFY(message, signature):
        """
        Verify an xmss sig with shorter PK
        same function but verifies using shorter signature where PK: {root, hex(public_SEED)}
        # main verification function..
        :param message:
        :param signature:
        :return:
        """
        if not verify_wpkey(signature[1], message, signature[4]):
            return False

        if not XMSS._verify_auth_SEED(signature[2], signature[3], signature[4], signature[5]):
            return False

        return True

    def address_add(self, i=None):
        """
        Derive new address from an xmss tree using the same SEED
        but i base leaves..allows deterministic address creation
        :param i:
        :return:
        """
        if i is None:
            i = self.signatures - len(self.addresses)

        if i > self.signatures or i < self.index:
            logger.error('i cannot be below signing index or above the pre-calculated signature count for xmss tree')
            return False

        xmss_array, x_bms, l_bms, privs, pubs = self._xmss_tree(i,
                                                                self.private_SEED,
                                                                self.public_SEED)

        i_PK = [''.join(xmss_array[-1]), hexlify(self.public_SEED)]
        new_addr = 'Q' + sha256(''.join(i_PK)) + sha256(sha256(''.join(i_PK)))[:4]

        self.addresses.append((len(self.addresses), new_addr, i))
        self.subtrees.append((len(self.subtrees), i, xmss_array, x_bms, i_PK))  # x_bms could be limited to the length..

        return new_addr

    def address_adds(self, start_i, stop_i):
        """
        Batch creation of multiple addresses..
        :param start_i:
        :param stop_i:
        :return:
        """
        if start_i > self.signatures or stop_i > self.signatures:
            logger.error('i cannot be greater than pre-calculated signature count for xmss tree')
            return False

        if start_i >= stop_i:
            logger.error('starting i must be lower than stop_i')
            return False

        for i in range(start_i, stop_i):
            self.address_add(i)

    def SIGN_subtree(self, msg, t=0):
        """
        Default to full xmss tree with max sigs
        :param msg:
        :param t:
        :return:
        """
        if len(self.addresses) < t + 1:
            logger.error('self.addresses new address does not exist')
            return False

        i = self.index
        if self.addresses[t][2] < i:
            logger.error('xmss index above address derivation i')
            return False

        logger.info(
            ('xmss signing subtree (', str(self.addresses[t][2]), ' signatures) with OTS n = ', str(self.index)))
        s = self.sign(msg, i)
        auth_route, i_bms = XMSS._xmss_route(self.subtrees[t][3], self.subtrees[t][2], i)
        self.index += 1
        self.remaining -= 1

        return i, s, auth_route, i_bms, self.pk(i), self.subtrees[t][4]

    def list_addresses(self):
        """
        List the addresses derived in the main tree
        :return:
        """
        addr_arr = []
        for addr in self.addresses:
            addr_arr.append(addr[1])

        return addr_arr

    def address_n(self, t):
        if len(self.addresses) < t + 1:
            logger.info('ERROR: self.addresses new address does not exist')
            return False

        return self.addresses[t][1]

    def hashchain(self, n=config.dev.blocks_per_epoch, epoch=0):
        """
        generates a 20,000th hash in iterative sha256 chain..derived from private SEED
        :param n:
        :param epoch:
        :return:
        """
        half = int(config.dev.blocks_per_epoch / 2)
        x = GEN(self.private_SEED, half + epoch, l=32)
        y = GEN(x, half, l=32)
        z = GEN(y, half, l=32)
        z = hexlify(z)
        # z = GEN_range(z, 1, 50)
        z = GEN_range(z, 1, config.dev.hashchain_nums)
        self.hc_seed = z
        hc = []
        for hash_chain in z:
            hc.append([hash_chain])

        self.hc_terminator = []
        for hash_chain in hc[:-1]:  # skip last element as it is reveal hash
            for x in range(n):
                hash_chain.append(sha256(hash_chain[-1]))
            self.hc_terminator.append(hash_chain[-1])

        for hash_chain in hc[-1:]:  # Reveal hash chain
            for x in range(n + 1):  # Extra hash to reveal one hash value
                hash_chain.append(sha256(hash_chain[-1]))
            self.hc_terminator.append(hash_chain[-1])
        self.hc = hc

    def hashchain_reveal(self, n=config.dev.blocks_per_epoch, epoch=0):
        half = int(config.dev.blocks_per_epoch / 2)
        x = GEN(self.private_SEED, half + epoch, l=32)
        y = GEN(x, half, l=32)
        z = GEN(y, half, l=32)
        z = hexlify(z)

        z = GEN_range(z, 1, config.dev.hashchain_nums)
        hc = []
        for hash_chain in z:
            hc.append([hash_chain])
        tmp_hc_terminator = []
        for hash_chain in hc[:-1]:
            for x in range(n):
                hash_chain.append(sha256(hash_chain[-1]))
            tmp_hc_terminator.append(hash_chain[-1])

        for hash_chain in hc[-1:]:
            for x in range(n + 1):
                hash_chain.append(sha256(hash_chain[-1]))
            tmp_hc_terminator.append(hash_chain[-1])

        return tmp_hc_terminator

    @staticmethod
    def _xmss_tree(n, private_SEED, public_SEED):
        # FIXME: Most other methods use pub/priv. Refactor?
        # no.leaves = 2^h
        h = ceil(log(n, 2))

        # generate the OTS keys, bitmasks and l_trees randomly (change to SEED+KEY PRF)

        leafs = []
        pubs = []
        privs = []

        # for random key generation: public_SEED: 14 = l_bm, 2n-2 - 2n+h = x_bm (see comment below)

        rand_keys = GEN_range(public_SEED, 1, 14 + 2 * n + int(h), 32)

        l_bms = rand_keys[:14]
        x_bms = rand_keys[14:]

        # generate n hexlified private key seeds from PRF

        sk_keys = GEN_range(private_SEED, 1, n, 32)

        for x in range(n):
            priv, pub = XMSS._xmss_random_wpkey(seed=sk_keys[x])
            leaf = XMSS._l_tree(pub, l_bms)
            leafs.append(leaf)
            pubs.append(pub)
            privs.append(priv)

        # create xmss tree with 2^n leaves, need 2 bitmasks per parent node (excluding layer 0), therefore for a perfect binary tree total nodes = 2*n_leaves-1
        # Given even an odd number we just create a bm for each node but dont use it for ease (the extra moves up to just below root) n_bm = 2*n-2 - 2n+h

        xmss_array = [leafs]

        p = 0
        for x in range(int(h)):
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
    def checkaddress(PK_short, address):
        sha_r1 = sha256(PK_short[0] + PK_short[1])
        sha_r2 = sha256(sha_r1)
        rootoaddr = 'Q' + sha_r1 + sha_r2[:4]
        return rootoaddr == address

    @staticmethod
    def _xmss_route(x_bms, x_tree, i=0):
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
                    logger.info(('Failed at height', str(x)))
                    return
                leaf = node
                i = x_tree[x + 1].index(leaf)

        return auth_route, i_bms

    @staticmethod
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

    @staticmethod
    def _verify_auth_SEED(auth_route, i_bms, pub, PK_short):
        """
        same as verify_auth but using the shorter PK which is {root, hex(public_SEED)} to reconstitute the long PK
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
        PK.append(rand_keys[14:])  # x_bms
        PK.append(rand_keys[:14])  # l_bms

        return XMSS._verify_auth(auth_route, i_bms, pub, PK)

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
    def _xmss_random_wpkey(seed, w=16, verbose=False):
        """
        first calculate l_1 + l_2 = l .. see whitepaper http://theqrl.org/whitepaper/QRL_whitepaper.pdf
        if using SHA-256 then m and n = 256
        :param seed:
        :param w:
        :param verbose:
        :return:
        """
        start_time = time.time()
        l, l_1, l_2 = get_lengths(w)

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
            pub.append(chain_fn(sk_, r, w - 1, k))

        if verbose:
            logger.info(str(time.time() - start_time))

        return priv, pub
