from pyqrllib.pyqrllib import hstr2bin, sha2_256, bin2hstr

from qrl.core.AddressState import AddressState
from qrl.core.misc.helper import parse_qaddress
from qrl.core.bech32 import convertbits, bech32_encode, bech32_decode

"""
In QRL, we have
Raw Addresses: descriptor+PK+SHA256 checksum
Qaddresses/hexaddresses: 'Q'+hstr2bin(raw address)
BECH32 Addresses: bech32_encode('q', descriptor+PK)
"""


def pk_to_b32address(ePK) -> str:
    """
    Notice the similarity between this func and raw_to_b32address().
    The raw address is simply SHA256(ePK) and its SHA256 suffix.
    """
    descriptor = ePK[0:3]
    descriptor_and_hash = descriptor + bytes(sha2_256(ePK))
    descriptor_and_hash_base32 = convertbits(descriptor_and_hash, 8, 5)
    return bech32_encode('q', descriptor_and_hash_base32)


def raw_to_b32address(address_raw: bytes) -> str:
    """
    Converts a raw Address (ePK + SHA256 checksum suffix) to a BECH32 Address
    Will remove the SHA256 checksum suffix because BECH32 has its own error detection
    """
    address_base32 = convertbits(address_raw[:35], 8, 5)
    return bech32_encode('q', address_base32)


def raw_to_hexaddress(address_raw: bytes) -> str:
    return 'Q{}'.format(bin2hstr(address_raw))


def hex_to_b32address(address: str) -> str:
    """
    Will remove the SHA256 checksum suffix because BECH32 has its own error detection
    :param address:
    :return:
    """
    address_raw = parse_qaddress(address)
    return raw_to_b32address(address_raw)


def hex_to_rawaddress(qaddress: str) -> bytes:
    """
    Converts from a Qaddress to an Address.
    qaddress: 'Q' + hexstring representation of an XMSS tree's address
    address: bytesary representation, the Q is ignored when transforming from qaddress.
    :param qaddress:
    :return:
    """
    try:
        address_raw = bytes(hstr2bin(qaddress[1:]))
        if not AddressState.address_is_valid(address_raw):
            raise ValueError("Invalid Addresss ", qaddress)
    except Exception as e:
        raise ValueError("Failed To Decode Hex Address", e)
    return address_raw


def b32_to_rawaddress(b32address: str) -> bytes:
    try:
        prefix, ePK_base32 = bech32_decode(b32address)
        ePK = convertbits(ePK_base32, 5, 8)
    except Exception as e:
        raise ValueError("Failed to Decode BECH32 Address", e)

    if prefix != 'q':
        raise ValueError("BECH32 Address did not have a q as its prefix! This is not a QRL Address.")

    hash = sha2_256(ePK)
    address_raw = bytes(ePK) + bytes(hash[28:])
    return address_raw


def b32_to_hexaddress(b32address: str) -> str:
    address_raw = b32_to_rawaddress(b32address)
    return raw_to_hexaddress(address_raw)


def any_to_rawaddress(address: str) -> bytes:
    if address[0] == 'Q' and len(address) == 79:
        return hex_to_rawaddress(address)
    return b32_to_rawaddress(address)
