# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class MockFunction:
    def __init__(self, default=None):
        self.data = dict()
        self.default = default

    def put(self, key, value):
        self.data[key] = value

    def get(self, key):
        if key in self.data:
            return self.data[key]

        return self.default

    def remove(self, key):
        del self.data[key]
