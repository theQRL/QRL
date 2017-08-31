"""
    48 byte SEED converted to a backup 32 word mnemonic wordlist to allow backup retrieval of keys and addresses.
    SEED parsed 12 bits at a time and a word looked up from a dictionary with 4096 unique words in it..
    another approach would be a hexseed and QR code or BIP38 style encryption of the SEED with a passphrase..
"""
from qrl.core import logger
from qrl.crypto.words import wordlist


def validate_mnemonic(mnemonic):
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
    mnemonic to seed
    takes a string..could use type or isinstance here..must be space not comma delimited..
    :param mnemonic:
    :return:
    """

    if not validate_mnemonic(mnemonic):
        raise ValueError("Mnemonic is not valid")

    words = mnemonic.lower().split()
    seed = ''
    y = 0
    for x in range(16):
        # TODO: Use a look up to improve efficiency
        n = format(wordlist.index(words[y]), '012b') + format(wordlist.index(words[y + 1]), '012b')
        seed += chr(int(n[:8], 2)) + chr(int(n[8:16], 2)) + chr(int(n[16:], 2))
        y += 2
    return seed


def seed_to_mnemonic(seed):
    """
    seed to mnemonic
    :param seed:
    :return:
    """
    if len(seed) != 48:
        logger.error('SEED is not 48 bytes in length..')
        return False
    words = []
    y = 0
    for x in range(16):
        three_bytes = format(ord(seed[y]), '08b') + format(ord(seed[y + 1]), '08b') + format(ord(seed[y + 2]), '08b')
        words.append(wordlist[int(three_bytes[:12], 2)])
        words.append(wordlist[int(three_bytes[12:], 2)])
        y += 3
    return ' '.join(words)
