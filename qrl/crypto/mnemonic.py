# coding=utf-8
"""
    48 byte SEED converted to a backup 32 word mnemonic wordlist to allow backup retrieval of keys and addresses.
    SEED parsed 12 bits at a time and a word looked up from a dictionary with 4096 unique words in it..
    another approach would be a hexseed and QR code or BIP38 style encryption of the SEED with a passphrase..
"""
from pyqrllib.pyqrllib import mnemonic2bin

from qrl.core import logger


def validate_mnemonic(mnemonic: str) -> bool:
    """
    validates a mnemonic
    :param mnemonic:
    :return: return True is the mnemonic is valid
    """
    words = mnemonic.lower().split()
    if len(words) != 32:
        logger.error('mnemonic is not 32 words in length..')
        return False

    try:
        mnemonic2bin(mnemonic)
    except Exception as e:
        logger.error('Invalid mnemonic %s', str(e))
        return False

    return True
