# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
# creates merkle trees for the MSS incorporating either lamport or winternitz OTS.
# creates winternitz OTS key pairs, signs and verifies a winternitz one time signature.
# creates lamport-diffie OTS key pairs, signs and verifies a lamport one time signature.
# creates winternitz OTS+ key pairs, signs and verifies the OTS.
# TODO: think about how can keep strings in hex..but need to go through and edit code such that we are passing sha256 binary strings rather than hex to avoid problems with specs..
# look at winternitz-ots fn_k to see if we need to pad it..

import hashlib
import time
from binascii import unhexlify
from math import ceil, floor, log

from qrl.core import logger
from qrl.crypto.hmac_drbg import random_key


def numlist(array):
    for a, b in enumerate(array):
        logger.info((a, b))
    return


def sha256(message):
    return hashlib.sha256(message).hexdigest()


def sha256b(message):
    return hashlib.sha256(message).digest()


def closest_hex(one, many):
    p = []
    for l in many:
        p.append(int(l, 16))

    return many[p.index(closest_number(int(one, 16), p))]


def closest_number(one, many):
    """
    return closest number in a list..
    :param one:
    :param many:
    :return:
    """
    return min(many, key=lambda x: abs(x - one))


def merkle_tx_hash(hashes):
    """
    merkle tree root hash of tx from pool for next POS block
    :param hashes:
    :return:
    """
    if len(hashes) == 64:  # if len = 64 then it is a single hash string rather than a list..
        return hashes
    j = int(ceil(log(len(hashes), 2)))
    l_array = [hashes]
    for x in range(j):
        next_layer = []
        i = len(l_array[x]) % 2 + len(l_array[x]) / 2
        z = 0
        for _ in range(i):
            if len(l_array[x]) == z + 1:
                next_layer.append(l_array[x][z])
            else:
                next_layer.append(sha256(l_array[x][z] + l_array[x][z + 1]))
            z += 2
        l_array.append(next_layer)

    return ''.join(l_array[-1])


def l_bm():
    """
    l_tree is composed of l pieces of pk (pk_1,..,pk_l) and uses the first (2 *ceil( log(l) )) bitmasks from the
    randomly generated bm array. where l = 67, # of bitmasks = 14, because h = ceil(log2(l) = 2^h = 7(inclusive..i.e
    0,8), and are 2 bm's per layer in tree, r + l
    :return:
    """
    bm = []
    for _ in range(14):
        bm.append(random_key())
    return bm


# winternitz ots+
# #need to generate a seed from PRF to populate sk_1->sk_l1, r and k. Otherwise need the public key and private key to sign..

def fn_k(x, k):
    return sha256(k + x)


def chain_fn(x, r, i, k):
    if i == 0:
        return x
    for y in range(i):
        x = fn_k(hex(int(x, 16) ^ int(r[y], 16))[2:-1], k)
    return x

def chain_fn2(x, r, i, k):
    for y in range(i, 15):
        x = fn_k(hex(int(x, 16) ^ int(r[y], 16))[2:-1], k)
    return x


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


def random_wpkey(w=16, verbose=False):
    """
    first calculate l_1 + l_2 = l .. see whitepaper http://theqrl.org/whitepaper/QRL_whitepaper.pdf
    if using SHA-256 then m and n = 256

    :param w:
    :param verbose:
    :return:
    """
    start_time = time.time()
    l, _, __ = get_lengths(w)

    sk = []
    pub = []

    # next create l+w-1 256 bit secret key fragments..(we will update this to use a PRF instead of random_key)
    # l n-bits will be private key, remaining w-1 will be r, the randomisation elements for the chaining function
    # finally generate k the key for the chaining function..

    for _ in range(l + w - 1):
        sk.append(random_key())

    priv = sk[:-(w - 1)]
    r = sk[l:]

    k = random_key()

    pub.append((r, k))  # pk_0 = (r,k) ..where r is a list of w-1 randomisation elements

    for sk_ in priv:
        pub.append(chain_fn(sk_, r, w - 1, k))

    if verbose:
        logger.info((str(time.time() - start_time)))

    return priv, pub


def sign_wpkey(priv, message, pub, w=16):
    l, l_1, l_2 = get_lengths(w)

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
    l, l_1, l_2 = get_lengths(w)

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
        # NOTE: Why is this using chain_fn2???
        pub2.append(chain_fn2(signature[x], pub[0][0], s[x], pub[0][1]))

    if pub2 == pub[1:]:
        return True

    return False
