# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from enum import Enum

import time
import os

from typing import Callable

from pyqryptonight.pyqryptonight import UInt256ToString
from qrl.core import config
from qrl.core.misc import logger
from qrl.core.notification.Observable import Observable
from qrl.core.notification.ObservableEvent import ObservableEvent
from qrl.core.p2pObserver import P2PBaseObserver
from qrl.generated import qrllegacy_pb2, qrl_pb2


class P2PPeerManager(P2PBaseObserver):
    class EventType(Enum):
        NO_PEERS = 1

    def __init__(self):
        super().__init__()
        self._ping_callLater = None
        self._disconnect_callLater = None
        self._channels = []

        self._peer_node_status = dict()

        self._peer_addresses = set()
        self.peers_path = os.path.join(config.user.data_dir,
                                       config.dev.peers_filename)

        self._observable = Observable(self)

        self._p2pfactory = None

    def register(self, message_type: EventType, func: Callable):
        self._observable.register(message_type, func)

    @property
    def peer_addresses(self):
        return self._peer_addresses

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
        config.create_path(config.user.data_dir)
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

    def get_better_difficulty(self, current_cumulative_difficulty):
        best_cumulative_difficulty = int(UInt256ToString(current_cumulative_difficulty))
        local_best = best_cumulative_difficulty
        best_channel = None

        for channel in self._peer_node_status:
            node_chain_state = self._peer_node_status[channel]
            node_cumulative_difficulty = int(UInt256ToString(node_chain_state.cumulative_difficulty))
            if node_cumulative_difficulty > best_cumulative_difficulty:
                best_cumulative_difficulty = node_cumulative_difficulty
                best_channel = channel
        logger.debug('Local Best Diff : %s', local_best)
        logger.debug('Remote Best Diff : %s', best_cumulative_difficulty)
        return best_channel

    def remove_channel(self, channel):
        self._channels.remove(channel)
        if channel in self._peer_node_status:
            del self._peer_node_status[channel]

    def new_channel(self, channel):
        self._channels.append(channel)
        self._peer_node_status[channel] = qrl_pb2.NodeChainState(block_number=0,
                                                                 header_hash=b'',
                                                                 cumulative_difficulty=b'\x00'*32,
                                                                 timestamp=int(time.time()))
        channel.register(qrllegacy_pb2.LegacyMessage.VE, self.handle_version)
        channel.register(qrllegacy_pb2.LegacyMessage.PL, self.handle_peer_list)
        channel.register(qrllegacy_pb2.LegacyMessage.CHAINSTATE, self.handle_chain_state)
        channel.register(qrllegacy_pb2.LegacyMessage.SYNC, self.handle_sync)
        channel.register(qrllegacy_pb2.LegacyMessage.P2P_ACK, self.handle_p2p_acknowledgement)

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
    def send_node_chain_state(dest_channel, node_chain_state: qrl_pb2.NodeChainState):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.CHAINSTATE,
                                          chainStateData=node_chain_state)
        dest_channel.send(msg)

    def monitor_chain_state(self):
        current_timestamp = time.time()
        for channel in self._channels:
            if channel not in self._peer_node_status:
                channel.loseConnection()
                continue
            delta = current_timestamp - self._peer_node_status[channel].timestamp
            if delta > config.user.chain_state_timeout:
                del self._peer_node_status[channel]
                logger.debug('>>>> No State Update [%18s] %2.2f (TIMEOUT)', channel.connection_id, delta)
                channel.loseConnection()

    def broadcast_chain_state(self, node_chain_state: qrl_pb2.NodeChainState):
        # TODO: Verify/Disconnect problematic channels
        # Ping all channels
        for channel in self._channels:
            self.send_node_chain_state(channel, node_chain_state)

        self._observable.notify(ObservableEvent(self.EventType.NO_PEERS))

    def handle_chain_state(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.CHAINSTATE)

        message.chainStateData.timestamp = int(time.time())  # Receiving time
        self._peer_node_status[source] = message.chainStateData

    def handle_p2p_acknowledgement(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.P2P_ACK)

        source.bytes_sent -= message.p2pAckData.bytes_processed
        if source.bytes_sent < 0:
            logger.warning('Disconnecting Peer %s', source.connection_id)
            logger.warning('Reason: negative bytes_sent value')
            logger.warning('bytes_sent %s', source.bytes_sent)
            logger.warning('Ack bytes_processed %s', message.p2pAckData.bytes_processed)
            source.loseConnection()

        source.send_next()
