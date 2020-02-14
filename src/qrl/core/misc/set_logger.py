import logging
import threading

from qrl.core.misc import logger, logger_twisted
from qrl.core import config

LOG_FORMAT_FULL = '%(asctime)s - %(levelname)s -  %(message)s'

LOG_FORMAT_CUSTOM = '%(asctime)s|%(version)s|%(node_state)s|%(thread_id)s| ' \
                    '%(levelname)s : %(message)s'


class ContextFilter(logging.Filter):
    def __init__(self, node_state, version):
        super(ContextFilter, self).__init__()
        self.node_state = node_state
        self.version = version

    def filter(self, record):
        record.node_state = "{:<8}".format(self.node_state.state.name)
        record.version = self.version
        record.thread_id = "{:<11}".format(threading.current_thread().name)
        return True


def set_logger(args, sync_state):
    log_level = logging.INFO
    if args.logLevel:
        log_level = getattr(logging, args.logLevel)

    logger.initialize_default(force_console_output=not args.quiet).setLevel(log_level)
    custom_filter = ContextFilter(sync_state, config.dev.version)
    logger.logger.addFilter(custom_filter)
    file_handler = logger.log_to_file(config.user.log_path)
    file_handler.addFilter(custom_filter)
    file_handler.setLevel(logging.DEBUG)
    logger.set_colors(not args.no_colors, LOG_FORMAT_CUSTOM)
    logger.set_unhandled_exception_handler()
    logger_twisted.enable_twisted_log_observer()


def set_logger_default():
    log_level = logging.ERROR

    logger.initialize_default(force_console_output=False).setLevel(log_level)
    custom_filter = ContextFilter("TEST", config.dev.version)
    logger.logger.addFilter(custom_filter)
    logger.set_colors(False, LOG_FORMAT_CUSTOM)
    logger.set_unhandled_exception_handler()
    logger_twisted.enable_twisted_log_observer()
