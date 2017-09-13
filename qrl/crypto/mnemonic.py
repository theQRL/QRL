# coding=utf-8
"""
    48 byte SEED converted to a backup 32 word mnemonic wordlist to allow backup retrieval of keys and addresses.
    SEED parsed 12 bits at a time and a word looked up from a dictionary with 4096 unique words in it..
    another approach would be a hexseed and QR code or BIP38 style encryption of the SEED with a passphrase..
"""
from qrl.core import logger
from qrl.crypto.words import wordlist


def validate_mnemonic(mnemonic):
    # type: () -> bool
    """
    validates a mnemonic
    :param mnemonic:
    :return: return True is the mnemonic is valid
    """
    words = mnemonic.lower().split()
    if len(words) != 32:
        logger.error('mnemonic is not 32 words in length..')
        return False

    for w in words:
        # TODO: Use a look up to improve efficiency
        if w not in wordlist:
            logger.error('invalid word')
            return False

    return True
