from qrl.core import logger
from qrl.crypto.merkle import random_generic
from qrl.crypto.misc import random_wkey, sha256, numlist


class WOTS(object):
    def __init__(self, signatures, index=0, verbose=0):
        self.signatures = signatures
        self.merkle_obj = []
        self.merkle_root = ''
        self.merkle_path = []
        self.state = 0
        self.type = 'WOTS'
        self.index = index
        self.concatpub = ""
        if verbose == 1:
            logger.info(('New W-OTS keypair generation ', str(self.index)))
        self.priv, self.pub = random_wkey(verbose=verbose)

        self.concatpub = ''.join(self.pub)
        self.pubhash = sha256(self.concatpub)
        return

    def screen_print(self):
        logger.info(numlist(self.priv))
        logger.info(numlist(self.pub))
        logger.info(self.concatpub)
        logger.info(self.pubhash)
        return


def random_wmss(number_signatures=4, verbose=False):
    """
        Create a w-ots mms with multiple signatures..
    :param number_signatures:
    :param verbose:
    :return:
    """
    return random_generic(WOTS, number_signatures, verbose)
