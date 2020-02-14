# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import sys
import logging
import traceback

import os
from colorlog import ColoredFormatter
from logging.handlers import RotatingFileHandler

LOG_NAME = 'qrl'

LOG_MAXBYTES = 100 * 1024 * 1024
LOG_FORMAT_FULL = '%(asctime)s - %(levelname)s -  %(message)s'
LOG_FORMAT_SMALL = '%(asctime)s - %(message)s'

logger = logging.getLogger(LOG_NAME)


# TODO: Use configuration file instead. Example https://fangpenlin.com/posts/2012/08/26/good-logging-practice-in-python/

def initialize_default(force_console_output=False, log_level=logging.DEBUG):
    logging_target = sys.stderr
    if sys.flags.interactive or force_console_output:
        logger.setLevel(log_level)
        logging_target = sys.stdout

    handler = logging.StreamHandler(logging_target)
    handler.setFormatter(logging.Formatter(LOG_FORMAT_FULL, None))
    logger.addHandler(handler)
    set_unhandled_exception_handler()
    return handler


def log_to_file(filename):
    dir_path = os.path.dirname(os.path.realpath(filename))
    os.makedirs(dir_path, exist_ok=True)
    handler = RotatingFileHandler(filename,
                                  mode='a',
                                  maxBytes=LOG_MAXBYTES,
                                  backupCount=2,
                                  encoding=None,
                                  delay=0)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return handler


def _unhandled_exception(etype, value, tb):
    tmp = ['Unhandled exception!\n']
    tmp.extend(traceback.format_exception(etype, value, tb))
    logger.fatal(''.join(tmp))


def set_unhandled_exception_handler():
    sys.excepthook = _unhandled_exception


def get_colors(format_string):
    return ColoredFormatter(
        "%(log_color)s" + format_string,
        datefmt=None,
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'white',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        },
        secondary_log_colors={},
        style='%'
    )


def set_colors(enable_colors, formatting):
    for h in logger.handlers:
        if enable_colors and isinstance(h, logging.StreamHandler):
            h.setFormatter(get_colors(formatting))
        else:
            h.setFormatter(logging.Formatter(formatting))


def debug(msg, *args, **kwargs):
    logger.debug(repr(msg)[1:-1], *args, **kwargs)


def info(msg, *args, **kwargs):
    try:
        logger.info(repr(msg)[1:-1], *args, **kwargs)
    except Exception:
        raise Exception


def warning(msg, *args, **kwargs):
    logger.warning(repr(msg)[1:-1], *args, **kwargs)


def error(msg, *args, **kwargs):
    logger.error(repr(msg)[1:-1], *args, **kwargs)


def exception(e):
    error_str = traceback.format_exception(None, e, e.__traceback__)
    logger.error(''.join(error_str))


def fatal(msg, *args, **kwargs):
    logger.fatal(repr(msg)[1:-1], *args, **kwargs)
