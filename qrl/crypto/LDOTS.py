from qrl.core import logger
from qrl.crypto.merkle import random_generic
from qrl.crypto.misc import random_lkey, sha256, numlist


class LDOTS(object):
    def __init__(self, signatures, index=0, verbose=0):
        self.signatures = signatures
        self.merkle_obj = []
        self.merkle_root = ''
        self.merkle_path = []
        self.state = 0
        self.type = 'LDOTS'
        self.index = index
        self.concatpub = ""
        if verbose == 1:
            logger.info(('New LD keypair generation ', str(self.index)))
        self.priv, self.pub = random_lkey()

        self.publist = [i for sub in self.pub for i in sub]  # convert list of tuples to list to allow cat.
        self.concatpub = ''.join(self.publist)
        self.pubhash = sha256(self.concatpub)
        return

    def screen_printL(self):
        logger.info((numlist(self.priv)))
        logger.info((numlist(self.pub)))
        logger.info(self.concatpub)
        logger.info(self.pubhash)
        return


def random_ldmss(number_signatures=4, verbose=False):
    """
        lamport-diffie merkle signature scheme
    :param number_signatures:
    :param verbose:
    :return:
    """
    return random_generic(LDOTS, number_signatures, verbose)
