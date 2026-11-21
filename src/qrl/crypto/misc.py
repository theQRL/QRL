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
EXTENDED_PK_SIZE = 67


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


def address_from_extended_pk(extended_pk: bytes) -> bytes:
    """
    Consensus rule for deriving an address from a 67 byte extended XMSS public
    key (3 descriptor bytes, then root and public seed).

    The address is a normalised 3 byte descriptor (hash function nibble, tree
    height nibble, zero), then SHA2-256 over the whole extended public key
    exactly as given, then the last 4 bytes of SHA2-256 over those 35 bytes.
    The signature-type nibble and the third descriptor byte of the key do not
    appear in the address descriptor, but they are part of the hashed bytes.
    A key whose address-format nibble is not SHA256_2X has no address.

    This is the rule qrllib v1.2.4 applied when mainnet was built. It is kept
    here rather than delegated to QRLHelper.getAddress so that a qrllib
    upgrade cannot change consensus: qrllib 1.2.8 and later refuse keys that
    v1.2.4 derived an address for.

    Raises ValueError for a key of the wrong size or address format.

    >>> pk = bytes(hstr2bin('010400' + '11' * 64))
    >>> bin2hstr(address_from_extended_pk(pk))
    '0104005885508e5ff29881adfbc309663caf06d2085d11c7baabd98796b337cd6777226ecb9f64'
    >>> address_is_well_formed(address_from_extended_pk(pk))
    True
    >>> address_from_extended_pk(b'')
    Traceback (most recent call last):
        ...
    ValueError: Invalid extended_pk size. It should be 67 bytes
    """
    if not isinstance(extended_pk, (bytes, bytearray)) or len(extended_pk) != EXTENDED_PK_SIZE:
        raise ValueError('Invalid extended_pk size. It should be %d bytes' % EXTENDED_PK_SIZE)
    if extended_pk[1] >> 4 != ADDRESS_FORMAT_SHA256_2X:
        raise ValueError('Address format type not supported')
    payload = bytes([extended_pk[0] & 0x0F, extended_pk[1] & 0x0F, 0]) + hashlib.sha256(extended_pk).digest()
    return payload + hashlib.sha256(payload).digest()[-ADDRESS_CHECKSUM_SIZE:]


def extended_pk_for_verification(extended_pk: bytes) -> bytes:
    """
    Returns the extended public key in the form signature verification uses.

    qrllib v1.2.4, which mainnet was built with, read only the hash function,
    tree height and address format from the descriptor when it verified an
    XMSS signature. The signature-type nibble and the third descriptor byte
    were ignored. They are cleared here before the key is handed to the
    library, so that verification gives the same answer whichever qrllib
    version is installed. Everything else is passed through unchanged, and a
    key of the wrong size is returned as it is for the library to reject.

    >>> bin2hstr(extended_pk_for_verification(bytes(hstr2bin('210401' + '11' * 64))))[:6]
    '010400'
    >>> extended_pk_for_verification(b'abc')
    b'abc'
    """
    if not isinstance(extended_pk, (bytes, bytearray)) or len(extended_pk) != EXTENDED_PK_SIZE:
        return extended_pk
    return bytes([extended_pk[0] & 0x0F, extended_pk[1], 0]) + bytes(extended_pk[ADDRESS_DESCRIPTOR_SIZE:])


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
