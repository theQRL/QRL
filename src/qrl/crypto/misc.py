# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from math import ceil, log

import hashlib
import itertools

from pyqrllib.pyqrllib import sha2_256, bin2hstr, hstr2bin, sha2_256_n  # noqa

ADDRESS_DESCRIPTOR_SIZE = 3
ADDRESS_HASH_SIZE = 32
ADDRESS_CHECKSUM_SIZE = 4
ADDRESS_SIZE = ADDRESS_DESCRIPTOR_SIZE + ADDRESS_HASH_SIZE + ADDRESS_CHECKSUM_SIZE
ADDRESS_FORMAT_SHA256_2X = 0


def address_is_well_formed(address: bytes) -> bool:
    """
    Consensus rule for address validity: 39 bytes, address-format nibble
    SHA256_2X, and the last 4 bytes equal to the tail of SHA2-256 over the
    first 35. Nothing else in the descriptor (hash function, signature type,
    height, reserved byte) is checked.

    This is the rule qrllib v1.2.4 applied when mainnet was built. It is kept
    here rather than delegated to QRLHelper.addressIsValid so that a qrllib
    upgrade cannot change consensus: qrllib 1.2.8-1.3.1 tightened that check
    and rejected addresses already on chain (theQRL/QRL#1816).

    >>> address_is_well_formed(bytes(hstr2bin('0c0d00e3acde5fa627b3c0f2d723108c265f16b9667a19d811b3c99ac329028ec8abf52fc5cca6')))
    True
    >>> address_is_well_formed(bytes(hstr2bin('0c0d00e3acde5fa627b3c0f2d723108c265f16b9667a19d811b3c99ac329028ec8abf52fc5cc00')))
    False
    >>> address_is_well_formed(b'')
    False
    """
    if not isinstance(address, (bytes, bytearray)) or len(address) != ADDRESS_SIZE:
        return False
    if address[1] >> 4 != ADDRESS_FORMAT_SHA256_2X:
        return False
    payload = address[:ADDRESS_DESCRIPTOR_SIZE + ADDRESS_HASH_SIZE]
    return hashlib.sha256(payload).digest()[-ADDRESS_CHECKSUM_SIZE:] == address[-ADDRESS_CHECKSUM_SIZE:]


def sha256(message: bytes) -> bytes:
    """
    :param message:
    :type message: Union[str, unicode]
    :return:
    :rtype: str

    >>> bin2hstr(sha256(b"test"))
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    >>> bin2hstr(sha256(b"another string"))
    '81e7826a5821395470e5a2fed0277b6a40c26257512319875e1d70106dcb1ca0'
    """
    return bytes(sha2_256(message))


def sha256_n(message: bytes, count) -> bytes:
    """
    Calculate hash n times on the same data

    >>> bin2hstr(sha256_n(b"test", 1))
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    >>> bin2hstr(sha256(sha256(b"test")))
    '954d5a49fd70d9b8bcdb35d252267829957f7ef7fa6c74f88419bdc5e82209f4'
    >>> bin2hstr(sha256_n(b"test", 2))
    '954d5a49fd70d9b8bcdb35d252267829957f7ef7fa6c74f88419bdc5e82209f4'
    """
    if count == 0:
        return message
    return bytes(sha2_256_n(message, count))


def merkle_tx_hash(hashes):
    # TODO: Clean this, move to C++
    # FIXME: Review and consider (CVE-2012-2459) and bitcoin source code
    """
    merkle tree root hash of tx from pool for next POW block
    :param hashes:
    :return:

    >>> bin2hstr(merkle_tx_hash([b'0', b'1']) ) # FIXME: This input is not realistic
    '938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4'
    >>> bin2hstr(merkle_tx_hash([b'0', b'1', b'2']) )
    '22073806c4a9967bed132107933c5ec151d602847274f6b911d0086c2a41adc0'
    >>> bin2hstr(merkle_tx_hash([b'0', b'1', b'2', b'3']) )
    'f16689fdb29d871013c77feede7231de127b7a2e8b4a9c020375408cfb51a241'
    >>> merkle_tx_hash(['938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4'])
    '938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4'
    >>> bin2hstr(merkle_tx_hash('938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4'))
    '938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4'
    >>> bin2hstr(merkle_tx_hash([b'0', b'938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4']))  # FIXME: This input is not realistic
    '40243e694d9c015d5097590bcc9df82683d8ba4006d58c6abb5e1a6bee5ec6dc'
    """
    if isinstance(hashes, str):
        # it is a single hash string rather than a list..
        return hstr2bin(hashes)

    if isinstance(hashes, list) and len(hashes) == 1:
        # it is a single hash string rather than a list..
        return hashes[0]

    j = int(ceil(log(len(hashes), 2)))
    l_array = [hashes]
    for x in range(j):
        next_layer = []
        i = len(l_array[x]) % 2 + len(l_array[x]) // 2
        z = 0
        for _ in range(i):
            if len(l_array[x]) == z + 1:
                next_layer.append(l_array[x][z])
            else:
                next_layer.append(sha256(l_array[x][z] + l_array[x][z + 1]))
            z += 2
        l_array.append(next_layer)

    # if len(l_array[-1]) == 1:
    #     return tuple(l_array[-1])

    res = bytes(itertools.chain(*l_array[-1]))

    return res
