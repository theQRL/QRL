# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import struct
from queue import PriorityQueue
from typing import Callable, Optional

from google.protobuf.json_format import MessageToJson
from pyqrllib.pyqrllib import bin2hstr  # noqa
from twisted.internet.protocol import Protocol, connectionDone

from qrl.core import config
from qrl.core.OutgoingMessage import OutgoingMessage
from qrl.core.misc import logger, ntp
from qrl.core.p2p.IPMetadata import IPMetadata
from qrl.core.p2p.p2pObservable import P2PObservable
from qrl.generated import qrllegacy_pb2, qrl_pb2

OUT_FACTOR = 0.9
IN_FACTOR = 2.2


# Rename to p2p channel
class P2PProtocol(Protocol):
    def __init__(self):
        self._buffer = bytes()

        # Need to use composition instead of inheritance here
        self._observable = P2PObservable(self)

        self.last_rate_limit_update = 0
        self.rate_limit = config.user.peer_rate_limit
        self.in_counter = 0
        self.out_counter = 0

        self.bytes_sent = 0
        self.outgoing_queue = PriorityQueue(maxsize=config.user.p2p_q_size)

        self._connected_at = ntp.getTime()
        self._valid_message_count = 0

    @property
    def peer(self):
        return IPMetadata(self.transport.getPeer().host, self.transport.getPeer().port)

    @property
    def host(self):
        return IPMetadata(self.transport.getHost().host, self.transport.getHost().port)

    @property
    def connected_at(self):
        return self._connected_at

    @property
    def valid_message_count(self):
        return self._valid_message_count

    @property
    def connection_time(self):
        return ntp.getTime() - self._connected_at

    @property
    def peer_manager(self):
        # FIXME: this is breaking encapsulation
        return self.factory._qrl_node.peer_manager

    @property
    def p2pchain_manager(self):
        # FIXME: this is breaking encapsulation
        return self.factory._qrl_node.p2pchain_manager

    @property
    def tx_manager(self):
        # FIXME: this is breaking encapsulation
        return self.factory._qrl_node.tx_manager

    def register(self, message_type, func: Callable):
        self._observable.register(message_type, func)

    def connectionMade(self):
        if self.factory.add_connection(self):
            self.peer_manager.new_channel(self)
            self.p2pchain_manager.new_channel(self)
            self.tx_manager.new_channel(self)

            self.send_peer_list()
            self.send_version_request()
        else:
            self.loseConnection()

    def connectionLost(self, reason=connectionDone):
        logger.debug('%s disconnected. remainder connected: %d', self.peer, self.factory.num_connections)

        self.factory.remove_connection(self)
        if self.peer_manager:
            self.peer_manager.remove_channel(self)

    def dataReceived(self, data: bytes) -> None:
        self._buffer += data
        total_read = len(self._buffer)

        if total_read > config.dev.max_bytes_out:
            logger.warning('Disconnecting peer %s', self.peer)
            logger.warning('Buffer Size %s', len(self._buffer))
            self.loseConnection()
            return

        read_bytes = [0]

        msg = None
        for msg in self._parse_buffer(read_bytes):
            self.update_counters()
            self.in_counter += 1
            if self.in_counter > self.rate_limit * IN_FACTOR:
                logger.warning("Rate Limit hit by %s %s", self.peer.ip, self.peer.port)
                self.peer_manager.ban_channel(self)
                return

            if self._valid_message_count < config.dev.trust_min_msgcount * 2:
                # Avoid overflows
                self._valid_message_count += 1

            self._observable.notify(msg)

        if msg is not None and read_bytes[0] and msg.func_name != qrllegacy_pb2.LegacyMessage.P2P_ACK:
            p2p_ack = qrl_pb2.P2PAcknowledgement(bytes_processed=read_bytes[0])
            msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.P2P_ACK,
                                              p2pAckData=p2p_ack)
            self.send(msg)

    def update_counters(self):
        time_diff = ntp.getTime() - self.last_rate_limit_update
        if time_diff > 60:
            self.out_counter = 0
            self.in_counter = 0
            self.last_rate_limit_update = ntp.getTime()
            return

    def send_next(self):
        self.update_counters()
        if self.out_counter >= self.rate_limit * OUT_FACTOR:
            return

        if self.bytes_sent < config.dev.max_bytes_out:
            outgoing_bytes = self.get_bytes_from_q()

            if outgoing_bytes:
                self.bytes_sent += len(outgoing_bytes)
                self.transport.write(outgoing_bytes)

    def get_bytes_from_q(self):
        outgoing_bytes = b''
        while not self.outgoing_queue.empty():
            outgoing_msg = self.outgoing_queue.get()[2]
            if not outgoing_msg.is_expired():
                wrapped_message = self._wrap_message(outgoing_msg.message)
                if wrapped_message is not None:
                    if len(wrapped_message) + len(outgoing_bytes) > config.dev.max_bytes_out:
                        self.outgoing_queue.put((outgoing_msg.priority, outgoing_msg.timestamp, outgoing_msg))
                        break
                    outgoing_bytes += wrapped_message

                    self.out_counter += 1
                    if self.out_counter >= self.rate_limit * OUT_FACTOR:
                        break

        return outgoing_bytes

    def send(self, message: qrllegacy_pb2.LegacyMessage):
        priority = self.factory.p2p_msg_priority[message.func_name]
        outgoing_msg = OutgoingMessage(priority, message)
        if self.outgoing_queue.full():
            logger.info("Outgoing Queue Full: Skipping Message Type %s", message.WhichOneof('data'))
            return
        self.outgoing_queue.put((outgoing_msg.priority, outgoing_msg.timestamp, outgoing_msg))
        self.send_next()

    def loseConnection(self):
        self.transport.loseConnection()

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Low-level serialization/connections/etc
    # FIXME: This is a temporary refactoring, it will be completely replaced before release

    @staticmethod
    def _wrap_message(protobuf_obj) -> Optional[bytes]:
        """
        Receives a protobuf object and encodes it as (length)(data)
        :return: the encoded message
        :rtype: bytes
        >>> veData = qrllegacy_pb2.VEData(version="version", genesis_prev_hash=b'genesis_hash')
        >>> msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE, veData=veData)
        >>> bin2hstr(P2PProtocol._wrap_message(msg))
        '000000191a170a0776657273696f6e120c67656e657369735f68617368'

                msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                          plData=qrllegacy_pb2.PLData(peer_ips=trusted_peers,
                                                                      public_port=config.user.p2p_public_port))

        >>> plData = qrllegacy_pb2.PLData(peer_ips=[])
        >>> msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL, plData=plData)
        >>> bin2hstr(P2PProtocol._wrap_message(msg))
        '0000000408012200'
        """
        data = protobuf_obj.SerializeToString()
        if len(data) == 0:
            logger.debug("Skipping message. Zero bytes. %s", MessageToJson(protobuf_obj, sort_keys=True))
            return None

        str_data_len = struct.pack('>L', len(data))
        return str_data_len + data

    def _parse_buffer(self, total_read):
        # FIXME: This parsing/wire protocol needs to be replaced
        """
        >>> from pyqrllib.pyqrllib import hstr2bin
        >>> p=P2PProtocol()
        >>> p._buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'+ \
                                       '000000191a170a0776657273696f6e120c67656e657369735f68617368'))
        >>> messages = p._parse_buffer([0])
        >>> len(list(messages))
        2
        """

        chunk_size = 0

        while self._buffer:
            if len(self._buffer) < 5:
                # Buffer is still incomplete as it doesn't have message size
                return

            ignore_skip = False

            try:
                chunk_size_raw = self._buffer[:4]
                chunk_size = struct.unpack('>L', chunk_size_raw)[0]  # is m length encoded correctly?

                if chunk_size <= 0:
                    logger.debug("<X< %s", bin2hstr(self._buffer))
                    raise Exception("Invalid chunk size <= 0")

                if chunk_size > config.dev.message_buffer_size:
                    raise Exception("Invalid chunk size > message_buffer_size")

                if len(self._buffer) - 4 < chunk_size:  # As 4 bytes includes chunk_size_raw
                    ignore_skip = True  # Buffer is still incomplete as it doesn't have message so skip moving buffer
                    return

                message_raw = self._buffer[4:4 + chunk_size]
                message = qrllegacy_pb2.LegacyMessage()
                message.ParseFromString(message_raw)
                yield message

            except Exception as e:  # no qa
                logger.warning("Problem parsing message. Banning+Dropping connection")
                logger.exception(e)
                self.peer_manager.ban_channel(self)

            finally:
                if not ignore_skip:
                    skip = 4 + chunk_size
                    self._buffer = self._buffer[skip:]
                    total_read[0] += skip

    ###################################################
    ###################################################
    ###################################################
    ###################################################

    def send_version_request(self):
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE,
                                          veData=qrllegacy_pb2.VEData())
        self.send(msg)

    def send_peer_list(self):
        """
        Get Peers
        Sends the peers list.
        :return:
        """
        trusted_peers = self.peer_manager.trusted_addresses
        logger.debug('<<< Sending connected peers to %s [%s]', self.peer, trusted_peers)

        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.PL,
                                          plData=qrllegacy_pb2.PLData(peer_ips=trusted_peers,
                                                                      public_port=config.user.p2p_public_port))

        self.send(msg)

    def send_sync(self, synced=False):
        state_str = ''
        if synced:
            state_str = 'Synced'

        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.SYNC,
                                          syncData=qrllegacy_pb2.SYNCData(state=state_str))
        self.send(msg)

    def send_fetch_block(self, block_idx):
        """
        Fetch Block n
        Sends request for the block number n.
        :return:
        """
        logger.info('<<<Fetching block: %s from %s', block_idx, self.peer)
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.FB,
                                          fbData=qrllegacy_pb2.FBData(index=block_idx))
        self.send(msg)

    def send_get_headerhash_list(self, current_block_height):
        start_blocknumber = max(0, current_block_height - config.dev.reorg_limit)
        node_header_hash = qrl_pb2.NodeHeaderHash(block_number=start_blocknumber,
                                                  headerhashes=[])
        msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.HEADERHASHES,
                                          nodeHeaderHash=node_header_hash)
        self.send(msg)
