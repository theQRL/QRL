# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# creates merkle trees for the MSS incorporating either lamport or winternitz OTS.

# creates winternitz OTS key pairs, signs and verifies a winternitz one time signature. 
# creates lamport-diffie OTS key pairs, signs and verifies a lamport one time signature.
# creates winternitz OTS+ key pairs, signs and verifies the OTS.
#

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
    for x in range(14):
        bm.append(random_key())
    return bm


# winternitz ots+
# #need to generate a seed from PRF to populate sk_1->sk_l1, r and k. Otherwise need the public key and private key to sign..

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
    l, l_1, l_2 = get_lengths(w)

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
        pub2.append(chain_fn2(signature[x], pub[0][0], s[x], pub[0][1]))

    if pub2 == pub[1:]:
        return True

    return False


def random_wkey(w=8, verbose=False):
    """
    winternitz ots
    create random W-OTS keypair
    Use F = SHA256/SHA512 and G = SHA256/512
    :param w:
    :param verbose:
    :return:
    """
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

    if verbose:
        logger.info(elapsed_time)

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
        logger.info('hashed public key not in merkle path')
        return False

    for x in range(len(merkle_path)):
        if len(merkle_path[x]) == 1:
            if ''.join(merkle_path[x]) == merkle_root:
                return True
            else:
                logger.info('root check failed')
                return False
        if sha256(merkle_path[x][0] + merkle_path[x][1]) not in merkle_path[x + 1]:
            logger.error('path authentication error')
            return False

    return False


def sign_mss(data, message, ots_key=0):
    if not data:
        return False

    if not message:
        return False

    if ots_key > len(data) - 1:
        raise Exception('OTS key number greater than available signatures')

    if data[0].type == 'WOTS':
        return sign_wkey(data[ots_key].priv, message)
    elif data[0].type == 'LDOTS':
        return sign_lkey(data[ots_key].priv, message)
