# coding=utf-8
"""
    48 byte SEED converted to a backup 32 word mnemonic wordlist to allow backup retrieval of keys and addresses.
    SEED parsed 12 bits at a time and a word looked up from a dictionary with 4096 unique words in it..
    another approach would be a hexseed and QR code or BIP38 style encryption of the SEED with a passphrase..
"""
from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr, hstr2bin, bin2mnemonic
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


def mnemonic_to_seed(mnemonic):
    """
    :param mnemonic:
    :type mnemonic: str
    :return:
    :rtype: Union[str, None]
    >>> bin2hstr( mnemonic2bin("monies hoarse knee socket dock ladder monk abide child junior gill snack gloss bigger pink air spray ponder horrid tube stack luxury recent vein nicely arrive adam short burst keep bright steer", wordlist))
    '8fd6b878fcf13e57a08fe00328776f5d3ce25e9166a5704fd42a946c9ec2d4f854b3af1d9670b4025c7c20a7791d9d6e'
    """
    # type: (str) -> str
    """
    mnemonic to seed
    takes a string..could use type or isinstance here..must be space not comma delimited..
    :param mnemonic:
    :return:
    """
    if not validate_mnemonic(mnemonic):
        raise ValueError("Mnemonic is not valid")

    data = mnemonic2bin(mnemonic, wordlist)
    return data

def seed_to_mnemonic(seed_hexstring):
    # type: (str) -> Union[str, None]
    # FIXME: the seed is expected as a hex string
    """
    seed to mnemonic
    :param seed_hexstring:
    :return:
    """

    data = hstr2bin(seed_hexstring);
    return bin2mnemonic(data, wordlist)
