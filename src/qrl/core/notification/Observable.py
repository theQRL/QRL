# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from typing import Callable

from qrl.core.misc import logger


class Observable(object):
    def __init__(self, source):
        # FIXME: Add mutexes
        self.source = source
        self._observers = dict()

    @property
    def observers_count(self):
        return len(self._observers)

    def register(self, message_type, func: Callable):
        # FIXME: Add mutexes
        self._observers.setdefault(message_type, []).append(func)

    def notify(self, message, force_delivery=False):
        # FIXME: Add mutexes
        observers = self._observers.get(message.func_name, [])

        if force_delivery and not observers:
            raise RuntimeError("Observer not registered for: %s" % message.func_name)

        for o in observers:
            try:
                o(self.source, message)
            except Exception as e:
                logger.debug("[%s] executing %s", self.source, message)
                logger.exception(e)
