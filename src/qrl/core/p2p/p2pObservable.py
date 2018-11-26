from qrl.core.notification.Observable import Observable
from qrl.generated import qrllegacy_pb2


class P2PObservable(Observable):
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

    def __init__(self, source):
        # FIXME: Add mutexes
        super().__init__(source)

    def notify(self, message: qrllegacy_pb2.LegacyMessage):
        # TODO: Add some p2p specific validation?
        super().notify(message)
