from qrl.core import config, logger
from qrl.core.p2pObserver import P2PBaseObserver
from qrl.core.p2pprotocol import P2PProtocol
from qrl.generated import qrllegacy_pb2


class P2PPeerManagement(P2PBaseObserver):
    def __init__(self):
        super().__init__()

    def new_channel(self, channel: P2PProtocol):
        channel._observable.register(qrllegacy_pb2.LegacyMessage.VE, self.handle_version)

    def handle_version(self, source: P2PProtocol, message: qrllegacy_pb2.LegacyMessage):
        """
        Version
        If version is empty, it sends the version & genesis_prev_headerhash.
        Otherwise, processes the content of data.
        In case of mismatches, it disconnects from the peer
        """
        self._validate_message(message, qrllegacy_pb2.LegacyMessage.VE)

        if not message.veData.version:
            msg = qrllegacy_pb2.LegacyMessage(
                func_name=qrllegacy_pb2.LegacyMessage.VE,
                veData=qrllegacy_pb2.VEData(version=config.dev.version,
                                            genesis_prev_hash=config.dev.genesis_prev_headerhash))

            source.send(msg)
            return

        logger.info('%s version: %s | genesis prev_headerhash %s',
                    source.peer_ip,
                    message.veData.version,
                    message.veData.genesis_prev_hash)

        if message.veData.genesis_prev_hash != config.dev.genesis_prev_headerhash:
            logger.warning('%s genesis_prev_headerhash mismatch', source.connection_id)
            logger.warning('Expected: %s', config.dev.genesis_prev_headerhash)
            logger.warning('Found: %s', message.veData.genesis_prev_hash)
            source.loseConnection()