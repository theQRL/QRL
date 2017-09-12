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


def mnemonic_to_seed(mnemonic):
    """

    :param mnemonic:
    :type mnemonic: str
    :return:
    :rtype: Union[str, None]
    >>> from binascii import hexlify; hexlify(mnemonic_to_seed("monies hoarse knee socket dock ladder monk abide child junior gill snack gloss bigger pink air spray ponder horrid tube stack luxury recent vein nicely arrive adam short burst keep bright steer"))
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

    words = mnemonic.lower().split()
    seed_hexstring = ''
    y = 0
    for x in range(16):
        # TODO: Use a look up to improve efficiency
        n = format(wordlist.index(words[y]), '012b') + format(wordlist.index(words[y + 1]), '012b')
        seed_hexstring += chr(int(n[:8], 2)) + chr(int(n[8:16], 2)) + chr(int(n[16:], 2))
        y += 2
    return seed_hexstring


def seed_to_mnemonic(seed_hexstring):
    # type: (str) -> Union[str, None]
    # FIXME: the seed is expected as a hex string
    """
    seed to mnemonic
    :param seed_hexstring:
    :return:
    >>> seed_to_mnemonic("ss") is None
    True
    """
    if len(seed_hexstring) != 48:
        logger.error('SEED is not 48 bytes in length..')
        return None

    words = []
    y = 0
    for x in range(16):
        three_bytes = format(ord(seed_hexstring[y]), '08b') + format(ord(seed_hexstring[y + 1]), '08b') + format(ord(seed_hexstring[y + 2]), '08b')
        words.append(wordlist[int(three_bytes[:12], 2)])
        words.append(wordlist[int(three_bytes[12:], 2)])
        y += 3
    return ' '.join(words)
