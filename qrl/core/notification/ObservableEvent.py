# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class ObservableEvent(object):
    def __init__(self, id):
        self.id = id

    def func_name(self):
        # FIXME: Adaptation to align with legacy message, refactor
        return self.id
