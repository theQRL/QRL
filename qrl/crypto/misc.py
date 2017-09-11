# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
from math import ceil, log


def sha256(message):
    """
    :param message:
    :type message: Union[str, unicode]
    :return:
    :rtype: str
    >>> sha256("test")
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    >>> sha256("another string")
    '81e7826a5821395470e5a2fed0277b6a40c26257512319875e1d70106dcb1ca0'
    """
    return hashlib.sha256(message).hexdigest()

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
