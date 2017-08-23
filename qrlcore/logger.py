# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import sys
import logging
from logging.handlers import RotatingFileHandler

LOG_NAME = 'qrl'

LOG_FILENAME_DEFAULT = 'qrl.log'
LOG_MAXBYTES = 100 * 1024 * 1024
LOG_FORMAT_FULL = '%(asctime)s - %(levelname)s -  %(message)s'
LOG_FORMAT_SMALL = '%(asctime)s - %(message)s'

logger = logging.getLogger(LOG_NAME)


# TODO: Use configuration file instead. Example https://fangpenlin.com/posts/2012/08/26/good-logging-practice-in-python/

def initialize_default(force_console_output=False):
    logging_target = sys.stderr
    if sys.flags.interactive or force_console_output:
        logger.setLevel(logging.INFO)
        logging_target = sys.stdout

    print("INIT")

    handler = logging.StreamHandler(logging_target)
    handler.setFormatter(logging.Formatter(LOG_FORMAT_FULL, None))
    logger.addHandler(handler)


def log_to_file(filename=LOG_FILENAME_DEFAULT):
    handler = RotatingFileHandler(filename,
                                  mode='a',
                                  maxBytes=LOG_MAXBYTES,
                                  backupCount=2,
                                  encoding=None,
                                  delay=0)
    logger.addHandler(handler)


def debug(msg, *args, **kwargs):
    logger.debug(msg, *args, **kwargs)


def error(msg, *args, **kwargs):
    logger.error(msg, *args, **kwargs)


def fatal(msg, *args, **kwargs):
    logger.fatal(msg, *args, **kwargs)


def info(msg, *args, **kwargs):
    logger.info(msg, *args, **kwargs)


def warn(msg, *args, **kwargs):
    logger.warn(msg, *args, **kwargs)


def warning(msg, *args, **kwargs):
    logger.warning(msg, *args, **kwargs)

# TODO: Finish clean up
# consensusFileName = 'consensus.log'
# consensus_handler = RotatingFileHandler(consensusFileName,
#                                         mode='a',
#                                         maxBytes=LOGMAXBYTES,
#                                         backupCount=2,
#                                         encoding=None,
#                                         delay=0)
# consensus_handler.setFormatter(no_formatter)
# consensus_handler.setLevel(logging.INFO)

# class PrintHelper:
#     def __init__(self, logger, nodeState):
#         self.logger = logger
#         self.nodeState = nodeState
#         self.enableLogging = True
#
#     def logger.info((self, data):
#         if hasattr(data, '__iter__'):
#             data = map(str, data)
#             data = " ".join(data)
#         else:
#             data = str(data)
#         if self.enableLogging:
#             self.logger.info('[' + self.nodeState.state + '] ' + data)
#         print '[' + self.nodeState.state + '|' + str(self.nodeState.epoch_diff) + '] ' + data

# def getLogger(name):
#     logger = logging.getLogger(name)
#     logger.setLevel(logging.INFO)
#     logger.addHandler(log_handler)
#     consensus = logging.getLogger("consensus_" + name)
#     consensus.setLevel(logging.INFO)
#     consensus.addHandler(consensus_handler)
#     return logger, consensus
