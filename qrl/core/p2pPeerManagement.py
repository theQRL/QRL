# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from twisted.internet import reactor

from qrl.core import config, logger
from qrl.core.p2pObserver import P2PBaseObserver
from qrl.core.p2pprotocol import P2PProtocol
from qrl.generated import qrllegacy_pb2


class P2PPeerManagement(P2PBaseObserver):
    def __init__(self):
        super().__init__()

    def new_channel(self, channel: P2PProtocol):
        channel.register(qrllegacy_pb2.LegacyMessage.VE, self.handle_version)
        channel.register(qrllegacy_pb2.LegacyMessage.PL, self.handle_peer_list)
        channel.register(qrllegacy_pb2.LegacyMessage.PONG, self.handle_pong)
        channel.register(qrllegacy_pb2.LegacyMessage.SYNC, self.handle_sync)

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

    def handle_peer_list(self, source: P2PProtocol, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.PL)

        if not config.user.enable_peer_discovery:
            return

        if message.plData.peer_ips is None:
            return

        new_ips = set(ip for ip in message.plData.peer_ips)
        new_ips.discard(source.host_ip)  # Remove local address

        source.factory.update_peer_addresses(new_ips)

        logger.info('%s peers data received: %s', source.peer_ip, new_ips)

    def handle_pong(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.PONG)

        self._disconnect_callLater.reset(config.user.ping_timeout)
        if self._ping_callLater.active():
            self._ping_callLater.cancel()

        self._ping_callLater = reactor.callLater(config.user.ping_frequency, self.send_pong)
        logger.debug('Received PONG from %s', self.connection_id)

    def handle_sync(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.SYNC)

        if message.syncData.state == 'Synced':
            self.factory.set_peer_synced(self, True)
        elif message.syncData.state == '':
            if self.factory.synced:
                msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                                  syncData=qrllegacy_pb2.SYNCData(state='Synced'))
                self.send(msg)
                self.factory.set_peer_synced(self, False)
