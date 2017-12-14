# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from threading import Timer

import time

import os

from qrl.core import config, logger
from qrl.core.p2pObserver import P2PBaseObserver
from qrl.generated import qrllegacy_pb2, qrl_pb2


class P2PPeerManager(P2PBaseObserver):
    def __init__(self):
        super().__init__()
        self._ping_callLater = None
        self._disconnect_callLater = None
        self._channels = []

        self._ping_timestamp = dict()
        self._ping_timer = None

        self.periodic_health_check()

        self._peer_addresses = set()
        self.peers_path = os.path.join(config.user.data_path,
                                       config.dev.peers_filename)

        self._p2pfactory = None  # FIXME: REMOVE. This is temporary

    @property
    def peer_addresses(self):
        return self._peer_addresses

    # FIXME: REMOVE. This is temporary
    def set_p2pfactory(self, p2pfactory):
        self._p2pfactory = p2pfactory

    def new_channel(self, channel):
        self._channels.append(channel)

        channel.register(qrllegacy_pb2.LegacyMessage.VE, self.handle_version)
        channel.register(qrllegacy_pb2.LegacyMessage.PL, self.handle_peer_list)
        channel.register(qrllegacy_pb2.LegacyMessage.PONG, self.handle_pong)
        channel.register(qrllegacy_pb2.LegacyMessage.SYNC, self.handle_sync)

    def load_peer_addresses(self) -> None:
        try:
            if os.path.isfile(self.peers_path):
                logger.info('Opening peers.qrl')
                with open(self.peers_path, 'rb') as infile:
                    known_peers = qrl_pb2.StoredPeers()
                    known_peers.ParseFromString(infile.read())

                    self._peer_addresses |= set([peer.ip for peer in known_peers.peers])
                    self._peer_addresses |= set(config.user.peer_list)
                    return

        except Exception as e:
            logger.warning("Error loading peers")
            logger.exception(e)

        logger.info('Creating peers.qrl')
        # Ensure the data path exists
        config.create_path(config.user.data_path)
        self.update_peer_addresses(config.user.peer_list)

        logger.info('Known Peers: %s', self._peer_addresses)

    def update_peer_addresses(self, peer_addresses: set) -> None:
        new_addresses = self._peer_addresses - set(peer_addresses)

        # FIXME: Probably will be refactored
        if self._p2pfactory is not None:
            for peer_address in new_addresses:
                self._p2pfactory.connect_peer(peer_address)

        self._peer_addresses |= set(peer_addresses)

        known_peers = qrl_pb2.StoredPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self._peer_addresses])
        with open(self.peers_path, "wb") as outfile:
            outfile.write(known_peers.SerializeToString())

    def handle_version(self, source, message: qrllegacy_pb2.LegacyMessage):
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

    def handle_peer_list(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.PL)

        if not config.user.enable_peer_discovery:
            return

        if message.plData.peer_ips is None:
            return

        new_peers = set(ip for ip in message.plData.peer_ips)
        new_peers.discard(source.host_ip)  # Remove local address
        logger.info('%s peers data received: %s', source.peer_ip, new_peers)
        self.update_peer_addresses(new_peers)

    def handle_sync(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.SYNC)

        # FIXME: Refactor this
        if message.syncData.state == 'Synced':
            source.factory.set_peer_synced(source, True)
        elif message.syncData.state == '':
            if source.factory.synced:
                source.send_sync(synced=True)
                source.factory.set_peer_synced(source, False)

    @staticmethod
    def send_ping(dest_channel):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PONG)
        dest_channel.send(msg)
        # logger.debug('<<<< PING [%18s]', dest_channel.connection_id)

    def periodic_health_check(self):
        # TODO: Verify/Disconnect problematic channels
        # Ping all channels
        for channel in self._channels:

            current_timestamp = time.time()
            if channel not in self._ping_timestamp:
                self._ping_timestamp[channel] = current_timestamp

            delta = current_timestamp - self._ping_timestamp[channel]
            if delta > config.user.ping_timeout:
                self._ping_timestamp.pop(channel, None)
                logger.debug('>>>> PING [%18s] %2.2f (TIMEOUT)', channel.connection_id, delta)
                channel.loseConnection()
            else:
                self.send_ping(channel)

        # FIXME: This may result in time drift
        self._ping_timer = Timer(config.user.ping_period, self.periodic_health_check)
        self._ping_timer.daemon = True
        self._ping_timer.start()

    def handle_pong(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.PONG)

        # current_timestamp = time.time()
        # delta = current_timestamp - self._ping_timestamp.get(source, current_timestamp)
        # logger.debug('>>>> PONG [%18s] %2.2f', source.connection_id, delta)
        self._ping_timestamp.pop(source, None)
