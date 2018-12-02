from qrl.core.notification.Observable import Observable
from qrl.generated import qrllegacy_pb2


class P2PObservable(Observable):
    """
    A P2PObservable is a base class for any class that has (network) events
    spontaneously happening to it (P2PProtocol).

    Whenever a network event happens, P2PObservable will call
    Observable.notify(), which looks up which events are registered to which
    actions and runs those actions accordingly.
    """

    def __init__(self, source):
        # FIXME: Add mutexes
        super().__init__(source)

    def notify(self, message: qrllegacy_pb2.LegacyMessage):
        # TODO: Add some p2p specific validation?
        super().notify(message)
