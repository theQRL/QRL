# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.generated import qrllegacy_pb2


class P2PBaseObserver(object):
    """
    This is the Observer pattern, except done with composition rather than
    inheritance.

    1. An Observable is created.

    2. Observable calls Observer.register().

    3. Observer is a collection of function handlers around a specific theme
    (say transactions).

    Observer.register() runs Observable.register(protobuf_message_type,
    one_of_Observer's_functions).
    """

    def __init__(self):
        pass

    @staticmethod
    def _validate_message(message: qrllegacy_pb2.LegacyMessage, expected_func_name):
        if message.func_name != expected_func_name:
            raise ValueError("Invalid func_name")

    def new_channel(self, channel):
        pass
