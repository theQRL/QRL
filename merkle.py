# Python hash signature library (quantum resistant)
#
# creates merkle trees for the MSS incorporating either lamport or winternitz OTS.

# creates winternitz OTS key pairs, signs and verifies a winternitz one time signature. 
# creates lamport-diffie OTS key pairs, signs and verifies a lamport one time signature.
# creates winternitz OTS+ key pairs, signs and verifies the OTS.
#
# creates XMSS trees with W-OTS+ using PRF (hmac_drbg)

# TODO: think about how can keep strings in hex..but need to go through and edit code such that we are passing sha256 binary strings rather than hex to avoid problems with specs..
# look at winternitz-ots fn_k to see if we need to pad it..

__author__ = 'pete'

from words import wordlist  # 4096 unique word list for mnemonic SEED retrieval..
import hmac
import hashlib
from binascii import unhexlify, hexlify
from math import ceil, floor, log
import time
from os import urandom

import configuration as c


# timing runs..

def t(n):
    start_time = time.time()
    z = XMSS(n)
    printL((str(time.time() - start_time)))
    return z


def t2(s, m):
    start_time = time.time()
    xmss_verify(m, s)
    printL((str(time.time() - start_time)))


def numlist(array):
    for a, b in enumerate(array):
        printL((a, b))
    return


# sha256 short form

def sha256(message):
    return hashlib.sha256(message).hexdigest()


def sha256b(message):
    return hashlib.sha256(message).digest()


# sample entropy from OS for true random numbers such as seeds and private keys

def random_key(n=32):  # returns a 256 bit hex encoded (64 bytes) random number
    return hexlify(urandom(n))


def SEED(n=48):  # returns a n-byte binary random string
    return urandom(n)


# pseudo random function generator (PRF) utilising hash-based message authentication code deterministic random bit generation (HMAC_DRBG)
# k, v = key and value..

class HMAC_DRBG():
    def __init__(self, entropy, personalisation_string="",
                 security_strength=256):  # entropy should be 1.5X length of strength..384 bits / 48 bytes
        self.security_strength = security_strength
        self.instantiate(entropy, personalisation_string)

    def hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def generate(self, num_bytes, requested_security_strength=256):
        if (num_bytes * 8) > 7500:
            raise RuntimeError("generate cannot generate more than 7500 bits in a single call.")

        if requested_security_strength > self.security_strength:
            raise RuntimeError(
                "requested_security_strength exceeds this instance's security_strength (%d)" % self.security_strength)

        # if self.reseed_counter >= 10001:
        if self.reseed_counter >= 20001:
            return None

        temp = b""

        while len(temp) < num_bytes:
            self.V = self.hmac(self.K, self.V)
            temp += self.V

        self.update(None)
        self.reseed_counter += 1

        return temp[:num_bytes]

    def reseed(self):
        self.update(entropy)
        self.reseed_counter = 1
        return

    def instantiate(self, entropy, personalisation_string=""):
        seed_material = entropy + personalisation_string

        self.K = b"\x00" * 32
        self.V = b"\x01" * 32

        self.update(seed_material)
        self.reseed_counter = 1
        return

    def update(self, seed_material=None):
        self.K = self.hmac(self.K, self.V + b"\x00" + (b"" if seed_material is None else seed_material))
        self.V = self.hmac(self.K, self.V)

        if seed_material is not None:
            self.K = self.hmac(self.K, self.V + b"\x01" + seed_material)
            self.V = self.hmac(self.K, self.V)

        return

    # PRF overlay functions


def GEN(SEED, i, l=32):  # generates l: 256 bit PRF hexadecimal string at position i. Takes >= 48 byte SEED..
    if i < 1:
        printL(('i must be integer greater than 0'))
        return
    z = HMAC_DRBG(SEED)
    for x in range(i):
        y = z.generate(l)
    return y


def GEN_range(SEED, start_i, end_i, l=32):  # returns start -> end iteration of hex PRF (inclusive at both ends)
    if start_i < 1:
        printL(('starting i must be integer greater than 0'))
        return
    z = HMAC_DRBG(SEED)
    random_arr = []
    for x in range(1, end_i + 1):
        y = hexlify(z.generate(l))
        if x >= start_i:
            random_arr.append(y)
    return random_arr


def GEN_range_bin(SEED, start_i, end_i, l=32):  # returns start -> end iteration of bin PRF (inclusive at both ends)
    if start_i < 1:
        printL(('starting i must be integer greater than 0'))
        return
    z = HMAC_DRBG(SEED)
    random_arr = []
    for x in range(1, end_i + 1):
        y = z.generate(l)
        if x >= start_i:
            random_arr.append(y)
    return random_arr


# seed creation for xmss scheme for an address. Take a 48 bytes entropy from os.random, generate two 48 byte keys..public_SEED and private_SEED
# public_SEED used to generate PK, private_SEED taken as seed for PRF to generate 2^h sk seeds from which to derive sk elements + r,k
# each private key has 67 sk elements + w-1 +k = 83 -> 339968 keys to generate for a 4096 xmss tree!
# so we take the private key seed and generate 4096 seeds with hmac_drbg, then generate 83 sk elements from each seed..
# it is vital therefore the original 48 byte seed is kept secret. A word file with 65536 words in it can then be used to generate a 24 word list to be kept by the user

def new_keys(seed=None,
             n=9999):  # four digit pin to separate the public and private by n iterations of PRF (n=9999 0.38s)
    if not seed:
        seed = SEED(48)
    private_SEED = GEN(seed, 1, l=48)
    public_SEED = GEN(seed, n, l=48)
    return seed, public_SEED, private_SEED


# 48 byte SEED converted to a backup 32 word mnemonic wordlist to allow backup retrieval of keys and addresses.
# SEED parsed 12 bits at a time and a word looked up from a dictionary with 4096 unique words in it..
# another approach would be a hexseed and QR code or BIP38 style encryption of the SEED with a passphrase..

# mnemonic back to SEED

def mnemonic_to_seed(
        mnemonic):  # takes a string..could use type or isinstance here..must be space not comma delimited..

    words = mnemonic.lower().split()
    if len(words) != 32:
        printL(('ERROR: mnemonic is not 32 words in length..'))
        return False
    SEED = ''
    y = 0
    for x in range(16):
        n = format(wordlist.index(words[y]), '012b') + format(wordlist.index(words[y + 1]), '012b')
        SEED += chr(int(n[:8], 2)) + chr(int(n[8:16], 2)) + chr(int(n[16:], 2))
        y += 2
    return SEED


# SEED to mnemonic

def seed_to_mnemonic(SEED):
    if len(SEED) != 48:
        printL(('ERROR: SEED is not 48 bytes in length..'))
        return False
    words = []
    y = 0
    for x in range(16):
        three_bytes = format(ord(SEED[y]), '08b') + format(ord(SEED[y + 1]), '08b') + format(ord(SEED[y + 2]), '08b')
        words.append(wordlist[int(three_bytes[:12], 2)])
        words.append(wordlist[int(three_bytes[12:], 2)])
        y += 3
    return ' '.join(words)


# hexSEED to SEED

def hexseed_to_seed(hexSEED):
    if len(hexSEED) != 96:
        return False
    return unhexlify(hexSEED)


# xmss python implementation

# An XMSS private key contains N = 2^h WOTS+ private keys, the leaf index idx of the next WOTS+ private key that has not yet been used
# and SK_PRF, an m-byte key for the PRF.

# The XMSS public key PK consists of the root of the binary hash tree and the bitmasks from xmss and l-tree.

# a class which creates an xmss wrapper. allows stateful signing from an xmss tree of signatures. 

class XMSS():
    def __init__(self, signatures, SEED=None):
        self.type = 'XMSS'
        self.index = 0
        if signatures > 4986:  # after this we need to update seed for PRF..
            signatures = 4986
        self.signatures = signatures  # number of OTS keypairs in tree to generate: n=512 2.7s, n=1024 5.6s, n=2048 11.3s, n=4096 22.1s, n=8192 44.4s, n=16384 89.2s
        self.remaining = signatures

        # use supplied 48 byte SEED, else create randomly from os to generate private and public seeds..
        self.SEED, self.public_SEED, self.private_SEED = new_keys(SEED)
        self.hexpublic_SEED = hexlify(self.public_SEED)
        self.hexprivate_SEED = hexlify(self.private_SEED)
        # create the mnemonic..
        self.hexSEED = hexlify(self.SEED)
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

    def index(self):  # return next OTS key to sign with
        return self.index

    def set_index(self, i):  # set the index
        self.index = i

    def sk(self, i=None):  # return OTS private key at position i
        if i == None:
            i = self.index
        return self.privs[i]

    def pk(self, i=None):  # return OTS public key at position i
        if i == None:
            i = self.index
        return self.pubs[i]

    def auth_route(self, i=0):  # calculate auth route for keypair i
        return xmss_route(self.x_bms, self.tree, i)

    def verify_auth(self, auth_route, i_bms, i=0):  # verify auth route using pk's
        return verify_auth(auth_route, i_bms, self.pk(i), self.PK)

    def verify_auth_SEED(self, auth_route, i_bms,
                         i=0):  # verify auth route using ots pk and shorter PK {root, public_SEED}
        return verify_auth_SEED(auth_route, i_bms, self.pk(i), self.PK_short)

    def sign(self, msg, i=0):
        return sign_wpkey(self.privs[i], msg, self.pubs[i])  # sign with OTS private key at position i

    def verify(self, msg, signature, i=0):  # verify OTS signature
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
        printL(('xmss signing with OTS n = ',
                str(self.index)))  # formal sign and increment the index to the next OTS to be used..
        s = self.sign(msg, i)
        auth_route, i_bms = xmss_route(self.x_bms, self.tree, i)
        self.index += 1
        self.remaining -= 1
        return i, s, auth_route, i_bms, self.pk(i), self.PK_short

    def VERIFY_long(self, msg, SIG):  # verify xmss sig
        return xmss_verify_long(msg, SIG)

    def VERIFY(self, msg, SIG):  # verify an xmss sig with shorter PK
        return xmss_verify(msg, SIG)

    def address_add(self,
                    i=None):  # derive new address from an xmss tree using the same SEED but i base leaves..allows deterministic address creation
        if i == None:
            i = self.signatures - len(self.addresses)
        if i > self.signatures or i < self.index:
            printL(('ERROR: i cannot be below signing index or above the pre-calculated signature count for xmss tree'))
            return False
        xmss_array, x_bms, l_bms, privs, pubs = xmss_tree(i, self.private_SEED, self.public_SEED)
        i_PK = [''.join(xmss_array[-1]), hexlify(self.public_SEED)]
        new_addr = 'Q' + sha256(''.join(i_PK)) + sha256(sha256(''.join(i_PK)))[:4]
        self.addresses.append((len(self.addresses), new_addr, i))
        self.subtrees.append((len(self.subtrees), i, xmss_array, x_bms, i_PK))  # x_bms could be limited to the length..
        return new_addr

    def address_adds(self, start_i, stop_i):  # batch creation of multiple addresses..
        if start_i > self.signatures or stop_i > self.signatures:
            printL(('ERROR: i cannot be greater than pre-calculated signature count for xmss tree'))
            return False
        if start_i >= stop_i:
            printL(('ERROR: starting i must be lower than stop_i'))
            return False

        for i in range(start_i, stop_i):
            self.address_add(i)
        return

    def SIGN_subtree(self, msg, t=0):  # default to full xmss tree with max sigs
        if len(self.addresses) < t + 1:
            printL(('ERROR: self.addresses new address does not exist'))
            return False
        i = self.index
        if self.addresses[t][2] < i:
            printL(('ERROR: xmss index above address derivation i'))
            return False
        printL(('xmss signing subtree (', str(self.addresses[t][2]), ' signatures) with OTS n = ', str(self.index)))
        s = self.sign(msg, i)
        auth_route, i_bms = xmss_route(self.subtrees[t][3], self.subtrees[t][2], i)
        self.index += 1
        self.remaining -= 1
        return i, s, auth_route, i_bms, self.pk(i), self.subtrees[t][4]

    def list_addresses(self):  # list the addresses derived in the main tree
        addr_arr = []
        for addr in self.addresses:
            addr_arr.append(addr[1])
        return addr_arr

    def address_n(self, t):
        if len(self.addresses) < t + 1:
            printL(('ERROR: self.addresses new address does not exist'))
            return False
        return self.addresses[t][1]

    def hashchain(self, n=c.blocks_per_epoch,
                  epoch=0):  # generates a 20,000th hash in iterative sha256 chain..derived from private SEED
        half = int(c.blocks_per_epoch / 2)
        x = GEN(self.private_SEED, half + epoch, l=32)
        y = GEN(x, half, l=32)
        z = GEN(y, half, l=32)
        z = hexlify(z)
        # z = GEN_range(z, 1, 50)
        z = GEN_range(z, 1, c.hashchain_nums)
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
            for x in range(n+1):  # Extra hash to reveal one hash value
                hash_chain.append(sha256(hash_chain[-1]))
            self.hc_terminator.append(hash_chain[-1])
        self.hc = hc
        return

    def hashchain_reveal(self, n=c.blocks_per_epoch, epoch=0):
        half = int(c.blocks_per_epoch / 2)
        x = GEN(self.private_SEED, half + epoch, l=32)
        y = GEN(x, half, l=32)
        z = GEN(y, half, l=32)
        z = hexlify(z)

        z = GEN_range(z, 1, c.hashchain_nums)
        hc = []
        for hash_chain in z:
            hc.append([hash_chain])
        tmp_hc_terminator = []
        for hash_chain in hc[:-1]:
            for x in range(n):
                hash_chain.append(sha256(hash_chain[-1]))
            tmp_hc_terminator.append(hash_chain[-1])

        for hash_chain in hc[-1:]:
            for x in range(n+1):
                hash_chain.append(sha256(hash_chain[-1]))
            tmp_hc_terminator.append(hash_chain[-1])

        return tmp_hc_terminator


def xmss_tree(n, private_SEED, public_SEED):
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
        priv, pub = random_wpkey_xmss(seed=sk_keys[x])
        leaf = l_tree(pub, l_bms)
        leafs.append(leaf)
        pubs.append(pub)
        privs.append(priv)

    # create xmss tree with 2^n leaves, need 2 bitmasks per parent node (excluding layer 0), therefore for a perfect binary tree total nodes = 2*n_leaves-1
    # Given even an odd number we just create a bm for each node but dont use it for ease (the extra moves up to just below root) n_bm = 2*n-2 - 2n+h 

    xmss_array = []
    xmss_array.append(leafs)

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


# generate the xmss tree merkle auth route for a given ots key (starts at 0)

def xmss_route(x_bms, x_tree, i=0):
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
                printL(('Failed..root'))
                return

        elif i == len(x_tree[x]) - 1 and leaf in x_tree[
                    x + 1]:  # for an odd node it goes up a level each time until it branches..
            i = x_tree[x + 1].index(leaf)
            n = nodehash_list.index(leaf)
            nodehash_list[n] = None  # stops at first duplicate in list..need next so wipe..

        else:
            n = nodehash_list.index(leaf)  # position in the list == bitmask..
            if i % 2 == 0:  # left leaf, go right..
                # printL((  'left'
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
                printL(('Failed at height', str(x)))
                return
            leaf = node
            i = x_tree[x + 1].index(leaf)

    return auth_route, i_bms


# verify an XMSS auth root path..requires the xmss authentication route, OTS public key and XMSS public key (containing merkle root, x and l bitmasks) and i
# regenerate leaf from pub[i] and l_bm, use auth route to navigate up merkle tree to regenerate the root and compare with PK[0]

def verify_auth(auth_route, i_bms, pub, PK):
    root = PK[0]
    x_bms = PK[1]
    l_bms = PK[2]

    leaf = l_tree(pub, l_bms)

    h = len(auth_route)

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


# same but using the shorter PK which is {root, hex(public_SEED)} to reconstitute the long PK with bitmasks then call above..

def verify_auth_SEED(auth_route, i_bms, pub, PK_short):
    PK = []
    root = PK_short[0]
    public_SEED = unhexlify(PK_short[1])

    rand_keys = GEN_range(public_SEED, 1, 14 + i_bms[-1][-1] + 1,
                          32)  # i_bms[-1][-1] is the last bitmask in the tree. +1 because it counts from 0.

    PK.append(root)
    PK.append(rand_keys[14:])  # x_bms
    PK.append(rand_keys[:14])  # l_bms

    return verify_auth(auth_route, i_bms, pub, PK)


# verify an XMSS signature: {i, s, auth_route, i_bms, pk(i), PK(root, x_bms, l_bms)}
# SIG is a list composed of: i, s, auth_route, i_bms, pk[i], PK

def xmss_verify_long(msg, SIG):
    if verify_wpkey(SIG[1], msg, SIG[4]) == False:
        return False

    if verify_auth(SIG[2], SIG[3], SIG[4], SIG[5]) == False:
        return False

    return True


# same function but verifies using shorter signature where PK: {root, hex(public_SEED)}
# main verification function..

def xmss_verify(msg, SIG):
    if verify_wpkey(SIG[1], msg, SIG[4]) == False:
        return False

    if verify_auth_SEED(SIG[2], SIG[3], SIG[4], SIG[5]) == False:
        return False

    return True


# l_tree is composed of l pieces of pk (pk_1,..,pk_l) and uses the first (2 *ceil( log(l) )) bitmasks from the randomly generated bm array.
# where l = 67, # of bitmasks = 14, because h = ceil(log2(l) = 2^h = 7(inclusive..i.e 0,8), and are 2 bm's per layer in tree, r + l

def l_bm():
    bm = []
    for x in range(14):
        bm.append(random_key())
    return bm


def l_tree(pub, bm, l=67):
    if l == 67:
        j = 7
    else:
        j = ceil(log(l, 2))

    l_array = []
    l_array.append(pub[1:])  # pk_0 = (r,k) - given with the OTS pk but not in the xmss tree..

    for x in range(j):
        next_layer = []
        i = len(l_array[x]) % 2 + len(l_array[x]) / 2
        z = 0
        for y in range(i):
            if len(l_array[x]) == z + 1:
                next_layer.append(l_array[x][z])
            else:
                # printL((  str(l_array[x][z])
                next_layer.append(sha256(hex(int(l_array[x][z], 16) ^ int(bm[2 * x], 16))[2:-1] + hex(
                    int(l_array[x][z + 1], 16) ^ int(bm[2 * x + 1], 16))[2:-1]))
            z += 2
        l_array.append(next_layer)
    return ''.join(l_array[-1])


# winternitz ots+               #need to generate a seed from PRF to populate sk_1->sk_l1, r and k. Otherwise need the public key and private key to sign..

def fn_k(x, k):
    return sha256(k + x)


def chain_fn(x, r, i, k):
    if i == 0:
        return x
    else:
        for y in range(i):
            x = fn_k(hex(int(x, 16) ^ int(r[y], 16))[2:-1], k)
    return x


def chain_fn2(x, r, i, k):
    for y in range(i, 15):
        x = fn_k(hex(int(x, 16) ^ int(r[y], 16))[2:-1], k)
    return x


def random_wpkey_xmss(seed, w=16, verbose=0):
    if verbose == 1:
        start_time = time.time()
    # first calculate l_1 + l_2 = l .. see whitepaper http://theqrl.org/whitepaper/QRL_whitepaper.pdf
    # if using SHA-256 then m and n = 256

    if w == 16:
        l = 67
        l_1 = 64
        l_2 = 3
    else:
        m = 256
        l_1 = ceil(m / log(w, 2))
        l_2 = floor(log((l_1 * (w - 1)), 2) / log(w, 2)) + 1
        l = int(l_1 + l_2)

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

    if verbose == 1:
        printL((str(time.time() - start_time)))
    return priv, pub


def random_wpkey(w=16, verbose=0):
    if verbose == 1:
        start_time = time.time()
    # first calculate l_1 + l_2 = l .. see whitepaper http://theqrl.org/whitepaper/QRL_whitepaper.pdf
    # if using SHA-256 then m and n = 256

    if w == 16:
        l = 67
        l_1 = 64
        l_2 = 3
    else:
        m = 256
        l_1 = ceil(m / log(w, 2))
        l_2 = floor(log((l_1 * (w - 1)), 2) / log(w, 2)) + 1
        l = int(l_1 + l_2)

    sk = []
    pub = []

    # next create l+w-1 256 bit secret key fragments..(we will update this to use a PRF instead of random_key)
    # l n-bits will be private key, remaining w-1 will be r, the randomisation elements for the chaining function
    # finally generate k the key for the chaining function..

    for x in range(l + w - 1):
        sk.append(random_key())

    priv = sk[:-(w - 1)]
    r = sk[l:]

    k = random_key()

    pub.append((r, k))  # pk_0 = (r,k) ..where r is a list of w-1 randomisation elements

    for sk_ in priv:
        pub.append(chain_fn(sk_, r, w - 1, k))

    if verbose == 1:
        printL((str(time.time() - start_time)))
    return priv, pub


def sign_wpkey(priv, message, pub, w=16):
    m = 256
    if w == 16:
        l_1 = 64
        l_2 = 3
        l = 67
    else:
        l_1 = ceil(m / log(w, 2))
        l_2 = floor(log((l_1 * (w - 1)), 2) / log(w, 2)) + 1
        l = int(l_1 + l_2)

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

    signature = []

    for x in range(int(l)):
        signature.append(chain_fn(priv[x], pub[0][0], s[x], pub[0][1]))

    return signature


def verify_wpkey(signature, message, pub, w=16):
    m = 256
    if w == 16:
        l_1 = 64
        l_2 = 3
        l = 67
    else:
        l_1 = ceil(m / log(w, 2))
        l_2 = floor(log((l_1 * (w - 1)), 2) / log(w, 2)) + 1
        l = int(l_1 + l_2)

    message = sha256(message)

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

    pub2 = []

    for x in range(int(l)):  # merkle.chain_fn(priv[0],pub[0][0],15,pub[0][1])
        pub2.append(chain_fn2(signature[x], pub[0][0], s[x], pub[0][1]))

    if pub2 == pub[1:]:
        return True

    return False


# winternitz ots

def random_wkey(w=8, verbose=0):  # create random W-OTS keypair
    # Use F = SHA256/SHA512 and G = SHA256/512
    if w > 16:
        w = 16  # too many hash computations to make this sensible.  16 = 3.75s, 8 = 0.01s 1024 bytes..
    priv = []
    pub = []
    start_time = time.time()
    for x in range(256 / w):
        a = random_key()
        priv.append(a)
        for y in range(2 ** w - 1):  # F
            a = sha256(a)
        pub.append(sha256(a))  # G (just in case we have a different f from g).

    elapsed_time = time.time() - start_time
    if verbose == 1:
        printL((elapsed_time))
    return priv, pub


def temp():
    priv = random_key()
    pub = priv
    for x in range(256):
        pub = sha256(pub)
    message = 'h'

    return priv, pub, message


def sign_wkey(priv, message):  # only works with 8 at present. havent separated the 'g' component yet.

    signature = []
    bin_msg = unhexlify(sha256(message))

    for y in range(len(priv)):
        s = priv[y]
        for x in range(256 - ord(bin_msg[y:y + 1])):
            s = sha256(s)
        signature.append(s)
    return signature


def verify_wkey(signature, message, pub):
    verify = []
    bin_msg = unhexlify(sha256(message))

    for x in range(len(signature)):
        a = signature[x]
        # f is all but last hash..
        for z in range(ord(bin_msg[x:x + 1])):
            a = sha256(a)
        # a = sha256(a)                               #g is the final hash, separate so can be changed..
        verify.append(a)

    if pub != verify:
        return False

    return True


# lamport-diffie ots

def sign_lkey(priv, message):  # perform lamport signature

    signature = []
    bin_lmsg = unhexlify(sha256(message))

    z = 0
    for x in range(len(bin_lmsg)):
        l_byte = bin(ord(bin_lmsg[x]))[
                 2:]  # [2:][-1:]      #generate a binary string of 8 bits for each byte of 32/256.

        while len(l_byte) < 8:  # pad the zero's up to 8
            l_byte = '0' + l_byte

        for y in range(0, 8):
            if l_byte[-1:] == '0':
                signature.append(priv[z][0])
                l_byte = l_byte[:-1]
                z += 1
            else:
                signature.append(priv[z][1])
                l_byte = l_byte[:-1]
                z += 1

    return signature


def verify_lkey(signature, message, pub):  # verify lamport signature

    bin_lmsg = unhexlify(sha256(message))
    verify = []
    z = 0

    for x in range(len(bin_lmsg)):
        l_byte = bin(ord(bin_lmsg[x]))[2:]  # generate a binary string of 8 bits for each byte of 32/256.

        while len(l_byte) < 8:  # pad the zero's up to 8
            l_byte = '0' + l_byte

        for y in range(0, 8):
            if l_byte[-1:] == '0':
                verify.append((sha256(signature[z]), pub[z][0]))
                l_byte = l_byte[:-1]
                z += 1
            else:
                verify.append((sha256(signature[z]), pub[z][1]))
                l_byte = l_byte[:-1]
                z += 1

    for p in range(len(verify)):
        if verify[p][0] == verify[p][1]:
            pass
        else:
            return False

    return True


def random_lkey(numbers=256):  # create random lamport signature scheme keypair

    priv = []
    pub = []

    for x in range(numbers):
        a, b = random_key(), random_key()
        priv.append((a, b))
        pub.append((sha256(a), sha256(b)))

    return priv, pub


# merkle signature scheme

def verify_mss(sig, data, message,
               ots_key=0):  # verifies that the sig is generated from pub..for now need to specify keypair..

    if not sig:
        return False

    if not message:
        return False

    if ots_key > len(data) - 1:
        raise Exception('OTS key higher than available signatures')

    if data[0].type == 'WOTS':
        return verify_wkey(sig, message, data[ots_key].pub)
    elif data[0].type == 'LDOTS':
        return verify_lkey(sig, message, data[ots_key].pub)


def verify_root(pub, merkle_root, merkle_path):
    if not pub:
        return False
    if not merkle_root:
        return False
    if not merkle_path:
        return False

    if len(pub) == 256:  # then LDOTS, need to add this to correctly concat the pub->pubhash
        pub = [i for sub in pub for i in sub]

    pubhash = sha256(''.join(pub))

    if pubhash not in merkle_path[0]:
        printL(('hashed public key not in merkle path'))
        return False

    for x in range(len(merkle_path)):
        if len(merkle_path[x]) == 1:
            if ''.join(merkle_path[x]) == merkle_root:
                return True
            else:
                printL(('root check failed'))
                return False
        if sha256(merkle_path[x][0] + merkle_path[x][1]) not in merkle_path[x + 1]:
            return False
            printL(('path authentication error'))

    return False


def sign_mss(data, message, ots_key=0):
    if not data:
        return False

    if not message:
        return False

    if ots_key > len(data) - 1:
        raise Exception('OTS key number greater than available signatures')
        return False

    if data[0].type == 'WOTS':
        return sign_wkey(data[ots_key].priv, message)
    elif data[0].type == 'LDOTS':
        return sign_lkey(data[ots_key].priv, message)


# winternitz merkle signature scheme

def random_wmss(signatures=4, verbose=0):  # create a w-ots mms with multiple signatures..
    begin = time.time()
    data = []
    pubhashes = []

    for x in range(signatures):
        data.append(WOTS(signatures, index=x, verbose=verbose))

    for i in range(len(data)):
        pubhashes.append(data[i].pubhash)

    a = Merkle(base=pubhashes, verbose=verbose)

    for y in range(signatures):
        data[y].merkle_root = ''.join(a.root)
        data[y].merkle_path = a.auth_lists[y]
        data[y].merkle_obj = a

    if verbose == 1:
        printL(('Total MSS time = ', str(time.time() - begin)))

    return data  # array of wots classes full of data.. and a class full of merkle


# lamport-diffie merkle signature scheme

def random_ldmss(signatures=4, verbose=0):
    begin = time.time()
    data = []
    pubhashes = []

    for x in range(signatures):
        data.append(LDOTS(signatures, index=x, verbose=verbose))

    for i in range(len(data)):
        pubhashes.append(data[i].pubhash)

    a = Merkle(base=pubhashes, verbose=verbose)

    for y in range(signatures):
        data[y].merkle_root = ''.join(a.root)
        data[y].merkle_path = a.auth_lists[y]
        data[y].merkle_obj = a
    if verbose == 1:
        printL(('Total MSS time = ', str(time.time() - begin)))

    return data


class LDOTS():
    def __init__(self, signatures, index=0, verbose=0):
        self.signatures = signatures
        self.merkle_obj = []
        self.merkle_root = ''
        self.merkle_path = []
        self.state = 0
        self.type = 'LDOTS'
        self.index = index
        self.concatpub = ""
        if verbose == 1:
            printL(('New LD keypair generation ', str(self.index)))
        self.priv, self.pub = random_lkey()

        self.publist = [i for sub in self.pub for i in sub]  # convert list of tuples to list to allow cat.
        self.concatpub = ''.join(self.publist)
        self.pubhash = sha256(self.concatpub)
        return

    def screen_printL(self):
        printL((numlist(self.priv)))
        printL((numlist(self.pub)))
        printL((self.concatpub))
        printL((self.pubhash))
        return


class WOTS():
    def __init__(self, signatures, index=0, verbose=0):
        self.signatures = signatures
        self.merkle_obj = []
        self.merkle_root = ''
        self.merkle_path = []
        self.state = 0
        self.type = 'WOTS'
        self.index = index
        self.concatpub = ""
        if verbose == 1:
            printL(('New W-OTS keypair generation ', str(self.index)))
        self.priv, self.pub = random_wkey(verbose=verbose)

        self.concatpub = ''.join(self.pub)
        self.pubhash = sha256(self.concatpub)
        return

    def screen_print(self):
        printL((numlist(self.priv)))
        printL((numlist(self.pub)))
        printL((self.concatpub))
        printL((self.pubhash))
        return


# merkle tree creation

class Merkle():
    def __init__(self, base=[], verbose=0):
        self.base = base
        self.verbose = verbose
        self.tree = []
        self.num_leaves = len(self.base)
        if not self.base:
            return
        else:
            self.create_tree()
            self.route_proof()

    def route_proof(self):  # need to add in error detection..
        start_time = time.time()
        self.auth_lists = []

        if self.verbose == 1:
            printL(('Calculating proofs: tree height ', str(self.height), ',', str(self.num_leaves), ' leaves'))

        for y in range(self.num_leaves):
            auth_route = []
            leaf = self.tree[0][y]
            for x in range(self.height):
                if len(self.tree[x]) == 1:
                    if self.tree[x] == self.root:
                        auth_route.append(self.root)
                        self.auth_lists.append(auth_route)
                    else:
                        printL(('Merkle route calculation failed @ root'))
                else:
                    nodes = self.tree[x]
                    nodes_above = self.tree[x + 1]
                    for node in nodes:
                        if leaf != node:
                            for nodehash in nodes_above:
                                if sha256(leaf + node) == nodehash:
                                    auth_route.append((leaf, node))  # binary hash is ordered
                                    leaf = nodehash
                                elif sha256(node + leaf) == nodehash:
                                    auth_route.append((node, leaf))
                                    leaf = nodehash
                                else:
                                    pass
        elapsed_time = time.time() - start_time
        if self.verbose == 1:
            printL((elapsed_time))

        return

    def create_tree(self):

        if self.num_leaves <= 2: # catch case for which log doesn't do the job
            num_branches = 1
        elif self.num_leaves <= 512:
            num_branches = int(ceil(log(num_leaves, 2)))

        self.num_branches = num_branches
        self.tree.append(self.base)

        hashlayer = self.base

        for x in range(num_branches):  # iterate through each layer of the merkle tree starting with the base layer
            temp_array = []
            cycles = len(hashlayer) % 2 + len(hashlayer) / 2
            y = 0
            for x in range(cycles):
                if y + 1 == len(hashlayer):
                    temp_array.append(str(hashlayer[y]))
                else:
                    temp_array.append(sha256(str(hashlayer[y]) + str(hashlayer[y + 1])))
                    y = y + 2

            self.tree.append(temp_array)
            hashlayer = temp_array
        self.root = temp_array
        self.height = len(self.tree)
        if self.verbose == 1:
            printL(('Merkle tree created with ' + str(self.num_leaves),
                    ' leaves, and ' + str(self.num_branches) + ' to root.'))
        return self.tree

    def check_item(self):
        return
