# Logging file, must be imported by other programs, 
# in order to log informations into log file

__author__ = 'cyyber'
import logging
from logging.handlers import RotatingFileHandler

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s -  %(message)s')
no_formatter = logging.Formatter('%(asctime)s - %(message)s')

logFileName = 'qrl.log'
consensusFileName = 'consensus.log'

my_handler = RotatingFileHandler(logFileName, mode='a', maxBytes=100 * 1024 * 1024,
                                 backupCount=2, encoding=None, delay=0)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)

consensus_handler = RotatingFileHandler(consensusFileName, mode='a', maxBytes=100 * 1024 * 1024,
                                        backupCount=2, encoding=None, delay=0)
consensus_handler.setFormatter(no_formatter)
consensus_handler.setLevel(logging.INFO)


class PrintHelper:
    def __init__(self, logger, nodeState):
        self.logger = logger
        self.nodeState = nodeState
        self.enableLogging = True

    def printL(self, data):
        if hasattr(data, '__iter__'):
            data = map(str, data)
            data = " ".join(data)
        else:
            data = str(data)
        if self.enableLogging:
            self.logger.info('[' + self.nodeState.state + '] ' + data)
        print '[' + self.nodeState.state + '|' + str(self.nodeState.epoch_diff) + '] ' + data


def getLogger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.addHandler(my_handler)
    consensus = logging.getLogger("consensus_" + name)
    consensus.setLevel(logging.INFO)
    consensus.addHandler(consensus_handler)
    return logger, consensus
