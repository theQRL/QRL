# coding=utf-8
from twisted.logger import LogLevel, globalLogPublisher

from qrl.core import logger

twisted_logger_mapping = {
    LogLevel.critical: logger.fatal,
    LogLevel.error: logger.error,
    LogLevel.warn: logger.warning,
    LogLevel.info: logger.info,
    LogLevel.debug: logger.debug
}


def twisted_log_observer(event):
    current_loglevel = event.get("log_level")

    # Filter
    # if current_loglevel != LogLevel.critical or current_loglevel != LogLevel.error:
    #     return

    f = twisted_logger_mapping[current_loglevel]
    if 'log_text' in event:
        f("[TWISTED] %s", event['log_text'])


def enable_twisted_log_observer():
    globalLogPublisher.addObserver(twisted_log_observer)
