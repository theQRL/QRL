# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
from enum import Enum
from typing import Callable

from pyqryptonight.pyqryptonight import UInt256ToString

from qrl.core import config
from qrl.core.misc import logger, ntp
from qrl.core.misc.expiring_set import ExpiringSet
from qrl.core.misc.helper import parse_peer_addr
from qrl.core.notification.Observable import Observable
from qrl.core.notification.ObservableEvent import ObservableEvent
from qrl.core.p2p.p2pObserver import P2PBaseObserver
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

        self.banned_peers_filename = os.path.join(config.user.wallet_dir, config.dev.banned_peers_filename)
        self._banned_peers = ExpiringSet(expiration_time=config.user.ban_minutes * 60,
                                         filename=self.banned_peers_filename)

        self._observable = Observable(self)
        self._p2pfactory = None

    def register(self, message_type: EventType, func: Callable):
        self._observable.register(message_type, func)

    @property
    def peer_addresses(self):
        return self._peer_addresses

    @property
    def trusted_addresses(self):
        return set([peer.addr_remote for peer in self._p2pfactory.connections if peer.trusted])

    @property
    def peer_node_status(self):
        return self._peer_node_status

    def load_peer_addresses(self) -> None:
        try:
            if os.path.isfile(self.peers_path):
                logger.info('Opening peers.qrl')
                with open(self.peers_path, 'rb') as infile:
                    known_peers = qrl_pb2.StoredPeers()
                    known_peers.ParseFromString(infile.read())

                    # FIXME: Refactor, move to json?
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

    @staticmethod
    def get_valid_peers(peer_ips, peer_ip, public_port):
        new_peers = set()
        tmp = list(peer_ips)
        tmp.append("{0}:{1}".format(peer_ip, public_port))

        for ip_port in tmp:
            try:
                parse_peer_addr(ip_port, True)
                new_peers.add(ip_port)
            except Exception as e:
                logger.warning("Invalid Peer Address {} sent by {} - {}".format(ip_port, peer_ip, e))

        return new_peers

    def update_peer_addresses(self, peer_addresses: set) -> None:
        new_addresses = set(peer_addresses) - self._peer_addresses

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
        if channel in self._channels:
            self._channels.remove(channel)
        if channel in self._peer_node_status:
            del self._peer_node_status[channel]

    def new_channel(self, channel):
        self._channels.append(channel)
        self._peer_node_status[channel] = qrl_pb2.NodeChainState(block_number=0,
                                                                 header_hash=b'',
                                                                 cumulative_difficulty=b'\x00' * 32,
                                                                 timestamp=ntp.getTime())
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
                                            genesis_prev_hash=config.dev.genesis_prev_headerhash,
                                            rate_limit=config.user.peer_rate_limit))

            source.send(msg)
            return

        logger.info('%s version: %s | genesis prev_headerhash %s',
                    source.peer_ip,
                    message.veData.version,
                    message.veData.genesis_prev_hash)

        source.rate_limit = min(config.user.peer_rate_limit, message.veData.rate_limit)

        if message.veData.genesis_prev_hash != config.dev.genesis_prev_headerhash:
            logger.warning('%s genesis_prev_headerhash mismatch', source.addr_remote)
            logger.warning('Expected: %s', config.dev.genesis_prev_headerhash)
            logger.warning('Found: %s', message.veData.genesis_prev_hash)
            source.loseConnection()

    def handle_peer_list(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.PL)

        if not config.user.enable_peer_discovery:
            return

        if not message.plData.peer_ips:
            return

        new_peers = self.get_valid_peers(message.plData.peer_ips,
                                         source.peer_ip,
                                         message.plData.public_port)
        new_peers.discard(source.host_ip)  # Remove local address

        logger.info('%s peers data received: %s', source.peer_ip, new_peers)
        self.update_peer_addresses(new_peers)

    def handle_sync(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.SYNC)
        if message.syncData.state == '':
            if source.factory.synced:
                source.send_sync(synced=True)

    @staticmethod
    def send_node_chain_state(dest_channel, node_chain_state: qrl_pb2.NodeChainState):
        # FIXME: Not sure this belongs to peer management
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.CHAINSTATE,
                                          chainStateData=node_chain_state)
        dest_channel.send(msg)

    def monitor_chain_state(self):
        # FIXME: Not sure this belongs to peer management
        current_timestamp = ntp.getTime()
        for channel in self._channels:
            if channel not in self._peer_node_status:
                channel.loseConnection()
                continue
            delta = current_timestamp - self._peer_node_status[channel].timestamp
            if delta > config.user.chain_state_timeout:
                del self._peer_node_status[channel]
                logger.debug('>>>> No State Update [%18s] %2.2f (TIMEOUT)', channel.addr_remote, delta)
                channel.loseConnection()

    def broadcast_chain_state(self, node_chain_state: qrl_pb2.NodeChainState):
        # FIXME: Not sure this belongs to peer management
        # TODO: Verify/Disconnect problematic channels
        # Ping all channels
        for channel in self._channels:
            self.send_node_chain_state(channel, node_chain_state)

        self._observable.notify(ObservableEvent(self.EventType.NO_PEERS))

    def handle_chain_state(self, source, message: qrllegacy_pb2.LegacyMessage):
        # FIXME: Not sure this belongs to peer management
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.CHAINSTATE)

        message.chainStateData.timestamp = ntp.getTime()  # Receiving time

        try:
            UInt256ToString(message.chainStateData.cumulative_difficulty)
        except ValueError:
            logger.warning('Invalid Cumulative Difficulty sent by peer')
            source.loseConnection()
            return

        self._peer_node_status[source] = message.chainStateData

    def handle_p2p_acknowledgement(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.P2P_ACK)

        source.bytes_sent -= message.p2pAckData.bytes_processed
        if source.bytes_sent < 0:
            logger.warning('Disconnecting Peer %s', source.addr_remote)
            logger.warning('Reason: negative bytes_sent value')
            logger.warning('bytes_sent %s', source.bytes_sent)
            logger.warning('Ack bytes_processed %s', message.p2pAckData.bytes_processed)
            source.loseConnection()

        source.send_next()

    ####################################################
    ####################################################
    ####################################################
    ####################################################
    def is_banned(self, addr_remote: str):
        return addr_remote in self._banned_peers

    def ban_peer(self, peer_obj):
        self._banned_peers.add(peer_obj.addr_remote)
        logger.warning('Banned %s', peer_obj.addr_remote)
        peer_obj.loseConnection()

    def connect_peers(self):
        logger.info('<<<Reconnecting to peer list: %s', self.peer_addresses)
        for peer_address in self.peer_addresses:
            if self.is_banned(peer_address):
                continue
            self._p2pfactory.connect_peer(peer_address)

    def get_peers_stat(self) -> list:
        peers_stat = []
        # Copying the list of keys, to avoid any change by other thread
        for source in list(self.peer_node_status.keys()):
            try:
                peer_stat = qrl_pb2.PeerStat(peer_ip=source.peer_ip.encode(),
                                             port=source.peer_port,
                                             node_chain_state=self.peer_node_status[source])
                peers_stat.append(peer_stat)
            except KeyError:
                # Ignore in case the key is deleted by other thread causing KeyError
                continue
        return peers_stat
