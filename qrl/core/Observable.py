# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from typing import Callable

from qrl.core import logger
from qrl.generated import qrllegacy_pb2


class Observable(object):
    def __init__(self, source):
        # FIXME: Add mutexes
        self.source = source
        self._observers = dict()

    def register(self, message_type, func: Callable):
        # FIXME: Add mutexes
        self._observers.setdefault(message_type, []).append(func)

    def notify(self, message: qrllegacy_pb2.LegacyMessage):
        # FIXME: Add mutexes
        observers = self._observers.get(message.func_name, [])
        for o in observers:
            try:
                o(self.source, message)
            except Exception as e:
                logger.debug("[%s] executing %s", self.source, message)
                logger.exception(e)
