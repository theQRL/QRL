# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class ObservableEvent(object):
    """
    This is the Observer pattern, but implemented with composition instead of
    inheritance. This means that instead of inheriting from this class (and
    getting the notify() method), the class that will be observed will have a
    self._observable. Then, the class will take care of calling
    self._observable.notify() whenever something relevant happens to it.

    Other "observer" classes will use Observable.register() to tell the observed
    class  "hey, if you receive this message_type, run my function at ..." When
    the observed class receives a message, it will run notify(), which will
    notify the corresponding observer classes that it received this message.
    """
    def __init__(self, event_id):
        self._event_id = event_id

    def func_name(self):
        # FIXME: Adaptation to align with legacy message, refactor
        return self._event_id
