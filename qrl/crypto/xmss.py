from binascii import hexlify

from qrl.core import logger, config
from qrl.crypto.hmac_drbg import new_keys, GEN, GEN_range
from qrl.crypto.misc import xmss_tree, sha256, xmss_route, verify_auth, verify_auth_SEED, sign_wpkey, verify_wpkey
from qrl.crypto.mnemonic import seed_to_mnemonic


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
        self.tree, self.x_bms, self.l_bms, self.privs, self.pubs = xmss_tree(n=signatures,
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
        self.addresses = [(0, self.address,
                           self.signatures)]  # position in wallet denoted by first number and address/tree by signatures

        self.subtrees = [(0, self.signatures, self.tree, self.x_bms,
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
        return xmss_route(self.x_bms, self.tree, i)

    def verify_auth(self, auth_route, i_bms, i=0):
        """
        Verify auth route using pk's
        :param auth_route:
        :param i_bms:
        :param i:
        :return:
        """
        return verify_auth(auth_route, i_bms, self.pk(i), self.PK)

    def verify_auth_SEED(self, auth_route, i_bms, i=0):
        """
        Verify auth route using ots pk and shorter PK {root, public_SEED}
        :param auth_route:
        :param i_bms:
        :param i:
        :return:
        """
        return verify_auth_SEED(auth_route, i_bms, self.pk(i), self.PK_short)

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
        auth_route, i_bms = xmss_route(self.x_bms, self.tree, i)
        return i, s, auth_route, i_bms, self.pk(i), self.PK  # SIG

    def SIGN_short(self, msg, i=0):
        s = self.sign(msg, i)
        auth_route, i_bms = xmss_route(self.x_bms, self.tree, i)
        return i, s, auth_route, i_bms, self.pk(i), self.PK_short  # shorter SIG due to SEED rather than bitmasks

    def SIGN(self, msg):
        i = self.index

        # formal sign and increment the index to the next OTS to be used..
        logger.info('xmss signing with OTS n = %s', str(self.index))
        s = self.sign(msg, i)
        auth_route, i_bms = xmss_route(self.x_bms, self.tree, i)
        self.index += 1
        self.remaining -= 1

        return i, s, auth_route, i_bms, self.pk(i), self.PK_short

    def VERIFY_long(self, msg, SIG):
        """
        Verify xmss sig
        :param msg:
        :param SIG:
        :return:
        """
        return xmss_verify_long(msg, SIG)

    def VERIFY(self, msg, SIG):
        """
        Verify an xmss sig with shorter PK
        :param msg:
        :param SIG:
        :return:
        """
        return xmss_verify(msg, SIG)

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

        xmss_array, x_bms, l_bms, privs, pubs = xmss_tree(i, self.private_SEED, self.public_SEED)
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
        auth_route, i_bms = xmss_route(self.subtrees[t][3], self.subtrees[t][2], i)
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


def xmss_verify_long(msg, SIG):
    """
    verify an XMSS signature: {i, s, auth_route, i_bms, pk(i), PK(root, x_bms, l_bms)}
    SIG is a list composed of: i, s, auth_route, i_bms, pk[i], PK
    :param msg:
    :param SIG:
    :return:
    """
    if not verify_wpkey(SIG[1], msg, SIG[4]):
        return False

    if not verify_auth(SIG[2], SIG[3], SIG[4], SIG[5]):
        return False

    return True


def xmss_verify(message, signature):
    """
    same function but verifies using shorter signature where PK: {root, hex(public_SEED)}
    # main verification function..
    :param message:
    :param signature:
    :return:
    """
    if not verify_wpkey(signature[1], message, signature[4]):
        return False

    if not verify_auth_SEED(signature[2], signature[3], signature[4], signature[5]):
        return False

    return True


def xmss_rootoaddr(PK_short):
    sha_r1 = sha256(PK_short[0] + PK_short[1])
    sha_r2 = sha256(sha_r1)
    return 'Q' + sha_r1 + sha_r2[:4]


def xmss_checkaddress(PK_short, address):
    return xmss_rootoaddr(PK_short) == address
