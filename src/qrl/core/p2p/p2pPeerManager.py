# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
from enum import Enum
from typing import Callable, Set, List
from ipaddress import IPv4Address

import simplejson as json
from pyqryptonight.pyqryptonight import UInt256ToString

from qrl.core import config
from qrl.core.misc import logger, ntp
from qrl.core.misc.expiring_set import ExpiringSet
from qrl.core.notification.Observable import Observable
from qrl.core.notification.ObservableEvent import ObservableEvent
from qrl.core.p2p.IPMetadata import IPMetadata
from qrl.core.p2p.p2pObserver import P2PBaseObserver
from qrl.core.p2p.p2pprotocol import P2PProtocol
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

        self._known_peers = set()
        self.peers_path = os.path.join(config.user.data_dir,
                                       config.dev.peers_filename)

        self.banned_peers_filename = os.path.join(config.user.wallet_dir, config.dev.banned_peers_filename)
        self._banned_peer_ips = ExpiringSet(expiration_time=config.user.ban_minutes * 60,
                                            filename=self.banned_peers_filename)

        self._observable = Observable(self)
        self._p2p_factory = None

    def register(self, message_type: EventType, func: Callable):
        self._observable.register(message_type, func)

    def set_p2p_factory(self, p2p_factory):
        self._p2p_factory = p2p_factory

    @property
    def known_peer_addresses(self):
        return self._known_peers

    def trusted_peer(self, channel: P2PProtocol):
        if self.is_banned(channel.peer):
            return False

        if channel.valid_message_count < config.dev.trust_min_msgcount:
            return False

        if channel.connection_time < config.dev.trust_min_conntime:
            return False

        return True

    @property
    def trusted_addresses(self):
        ip_public_port_set = set()
        for peer in self._p2p_factory.connections:
            if self.trusted_peer(peer) and peer.public_port != 0:
                ip_public_port_set.add(peer.ip_public_port)
        return ip_public_port_set

    @property
    def peer_node_status(self):
        return self._peer_node_status

    def load_known_peers(self) -> List[str]:
        known_peers = []
        try:
            logger.info('Loading known peers')
            with open(self.peers_path, 'r') as infile:
                known_peers = json.load(infile)
        except Exception as e:
            logger.info("Could not open known_peers list")

        return [IPMetadata.canonical_full_address(fa) for fa in known_peers]

    def save_known_peers(self, known_peers: List[str]):
        tmp = list(known_peers)[:3 * config.user.max_peers_limit]
        config.create_path(config.user.data_dir)
        with open(self.peers_path, 'w') as outfile:
            json.dump(tmp, outfile)

    def load_peer_addresses(self) -> None:
        known_peers = self.load_known_peers()
        self._known_peers = self.combine_peer_lists(known_peers, config.user.peer_list, )
        logger.info('Loaded known peers: %s', self._known_peers)
        self.save_known_peers(self._known_peers)

    def extend_known_peers(self, new_peer_addresses: set) -> None:
        new_addresses = set(new_peer_addresses) - self._known_peers

        if self._p2p_factory is not None:
            self._p2p_factory.connect_peer(new_addresses)

        self._known_peers |= set(new_peer_addresses)
        self.save_known_peers(list(self._known_peers))

    @staticmethod
    def combine_peer_lists(peer_ips, sender_full_addresses: List, check_global=False) -> Set[IPMetadata]:
        tmp_list = list(peer_ips)
        tmp_list.extend(sender_full_addresses)

        answer = set()
        for item in tmp_list:
            try:
                answer.add(IPMetadata.canonical_full_address(item, check_global))
            except:  # noqa
                logger.warning("Invalid Peer Address {}".format(item))

        return answer

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

    def insert_to_last_connected_peer(self, ip_public_port, connected_peer=False):
        known_peers = self.load_known_peers()
        connection_set = set()

        if self._p2p_factory is not None:
            # Prepare set of connected peers
            for conn in self._p2p_factory._peer_connections:
                connection_set.add(conn.ip_public_port)

        # Move the current peer to the last position of connected peers
        # or to the start position of disconnected peers
        try:
            index = 0
            if connected_peer:
                if ip_public_port in known_peers:
                    known_peers.remove(ip_public_port)
            else:
                index = known_peers.index(ip_public_port)
                del known_peers[index]

            while index < len(known_peers):
                if known_peers[index] not in connection_set:
                    break
                index += 1
            known_peers.insert(index, ip_public_port)
            self.save_known_peers(known_peers)
        except ValueError:
            pass

    def remove_channel(self, channel):
        self.insert_to_last_connected_peer(channel.ip_public_port)
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

    def _get_version_compatibility(self, version) -> bool:
        # Ignore compatibility test on Testnet
        if config.dev.hard_fork_heights == config.dev.testnet_hard_fork_heights:
            return True

        if self._p2p_factory is None:
            return True
        if self._p2p_factory.chain_height >= config.dev.hard_fork_heights[0]:
            try:
                major_version = version.split(".")[0]
                if int(major_version) < 2:
                    return False
            except Exception:
                # Disabled warning as it is not required and could be annoying
                # if a peer with dirty version is trying to connect with the node
                # logger.warning("Exception while checking version for compatibility")
                return True

        if self._p2p_factory.chain_height >= config.dev.hard_fork_heights[1]:
            try:
                major_version = version.split(".")[0]
                if int(major_version) < 3:
                    return False
            except Exception:
                # Disabled warning as it is not required and could be annoying
                # if a peer with dirty version is trying to connect with the node
                # logger.warning("Exception while checking version for compatibility")
                return True

        hard_fork_2 = config.dev.hard_fork_heights[2] + config.dev.hard_fork_node_disconnect_delay[2]
        if self._p2p_factory.chain_height >= hard_fork_2:
            try:
                major_version = version.split(".")[0]
                if int(major_version) < 4:
                    return False
            except Exception:
                # Disabled warning as it is not required and could be annoying
                # if a peer with dirty version is trying to connect with the node
                # logger.warning("Exception while checking version for compatibility")
                return True

        return True

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
                                            genesis_prev_hash=config.user.genesis_prev_headerhash,
                                            rate_limit=config.user.peer_rate_limit))

            source.send(msg)
            return

        logger.info('%s version: %s | genesis prev_headerhash %s',
                    source.peer.ip,
                    message.veData.version,
                    message.veData.genesis_prev_hash)

        if not self._get_version_compatibility(message.veData.version):
            logger.warning("Disconnecting from Peer %s running incompatible node version %s",
                           source.peer.ip,
                           message.veData.version)
            source.loseConnection()
            self.ban_channel(source)
            return

        source.rate_limit = min(config.user.peer_rate_limit, message.veData.rate_limit)

        if message.veData.genesis_prev_hash != config.user.genesis_prev_headerhash:
            logger.warning('%s genesis_prev_headerhash mismatch', source.peer)
            logger.warning('Expected: %s', config.user.genesis_prev_headerhash)
            logger.warning('Found: %s', message.veData.genesis_prev_hash)
            source.loseConnection()
            self.ban_channel(source)

    def handle_peer_list(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.PL)

        if not config.user.enable_peer_discovery:
            return

        if not message.plData.peer_ips:
            return

        # If public port is invalid, ignore rest of the data
        if not (0 < message.plData.public_port < 65536):
            return

        source.set_public_port(message.plData.public_port)

        self.insert_to_last_connected_peer(source.ip_public_port, True)

        sender_peer = IPMetadata(source.peer.ip, message.plData.public_port)

        # Check if peer list contains global ip, if it was sent by peer from a global ip address
        new_peers = self.combine_peer_lists(message.plData.peer_ips,
                                            [sender_peer.full_address],
                                            check_global=IPv4Address(source.peer.ip).is_global)

        logger.info('%s peers data received: %s', source.peer.ip, new_peers)
        if self._p2p_factory is not None:
            self._p2p_factory.add_new_peers_to_peer_q(new_peers)

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
                logger.debug('>>>> No State Update [%18s] %2.2f (TIMEOUT)', channel.peer, delta)
                channel.loseConnection()

    def broadcast_chain_state(self, node_chain_state: qrl_pb2.NodeChainState):
        # FIXME: Not sure this belongs to peer management
        # TODO: Verify/Disconnect problematic channels
        # Ping all channels
        for channel in self._channels:
            self.send_node_chain_state(channel, node_chain_state)

        self._observable.notify(ObservableEvent(self.EventType.NO_PEERS))

    def handle_chain_state(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.CHAINSTATE)

        message.chainStateData.timestamp = ntp.getTime()  # Receiving time

        try:
            UInt256ToString(message.chainStateData.cumulative_difficulty)
        except ValueError:
            logger.warning('Invalid Cumulative Difficulty sent by peer')
            source.loseConnection()
            return

        self._peer_node_status[source] = message.chainStateData

        if not self._get_version_compatibility(message.chainStateData.version):
            logger.warning("Disconnecting from Peer %s running incompatible node version %s",
                           source.peer.ip,
                           message.veData.version)
            source.loseConnection()
            return

    def handle_p2p_acknowledgement(self, source, message: qrllegacy_pb2.LegacyMessage):
        P2PBaseObserver._validate_message(message, qrllegacy_pb2.LegacyMessage.P2P_ACK)

        source.bytes_sent -= message.p2pAckData.bytes_processed
        if source.bytes_sent < 0:
            logger.warning('Disconnecting Peer %s', source.peer)
            logger.warning('Reason: negative bytes_sent value')
            logger.warning('bytes_sent %s', source.bytes_sent)
            logger.warning('Ack bytes_processed %s', message.p2pAckData.bytes_processed)
            source.loseConnection()

        source.send_next()

    ####################################################
    ####################################################
    ####################################################
    ####################################################
    def is_banned(self, peer: IPMetadata):
        return peer.ip in self._banned_peer_ips

    def ban_channel(self, channel: P2PProtocol):
        self._banned_peer_ips.add(channel.peer.ip)
        logger.warning('Banned %s', channel.peer.ip)
        channel.loseConnection()

    def get_peers_stat(self) -> list:
        peers_stat = []
        # Copying the list of keys, to avoid any change by other thread
        for source in list(self.peer_node_status.keys()):
            try:
                peer_stat = qrl_pb2.PeerStat(peer_ip=source.peer.ip.encode(),
                                             port=source.peer.port,
                                             node_chain_state=self.peer_node_status[source])
                peers_stat.append(peer_stat)
            except KeyError:
                # Ignore in case the key is deleted by other thread causing KeyError
                continue
        return peers_stat
