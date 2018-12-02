# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.generated import qrllegacy_pb2


class P2PBaseObserver(object):
    """
    This is the Observer pattern, except done with composition rather than
    inheritance.

    To know what to do when the events happen to it, the Observable has to
    register events with actions, which are bundled into Observer classes. For
    instance, P2PTxManagement is a P2PObserver that has functions that describe
    what to do if Transactions come in over the network.

    The registration (pairing of a network event to an action) process:
    1. An Observable is created.
    2. Observable calls Observer.register().
    3. Observer.register() runs Observable.register(protobuf_message_type,
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
