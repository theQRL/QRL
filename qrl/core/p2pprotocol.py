# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import struct

from pyqrllib.pyqrllib import bin2hstr  # noqa
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, connectionDone

from qrl.core import config, logger
from qrl.generated import qrllegacy_pb2


class P2PProtocol(Protocol):
    def __init__(self):
        self._buffer = b''
        self._conn_identity = ""
        self._disconnect_callLater = None
        self._ping_callLater = None

        # FIXME: TO BE REMOVED
        self._services = {}

    @property
    def peer_ip(self):
        return self.transport.getPeer().host

    @property
    def peer_port(self):
        return self.transport.getPeer().port

    @property
    def host_ip(self):
        return self.transport.getHost().host

    def connectionMade(self):
        self._conn_identity = "{}:{}".format(self.transport.getPeer().host, self.transport.getPeer().port)

        if self.factory.add_connection(self):
            self.send_peer_list()
            self.send_version_request()

        self._ping_callLater = reactor.callLater(1, self.send_pong)
        self._disconnect_callLater = reactor.callLater(config.user.ping_timeout,
                                                       self.transport.loseConnection)

    def connectionLost(self, reason=connectionDone):
        logger.info('%s disconnected. remainder connected: %s',
                    self.transport.getPeer().host,
                    str(self.factory.connections))  # , reason

        self.factory.remove_connection(self)

    def dataReceived(self, data: bytes) -> None:
        self._buffer += data
        for msg in self._parse_buffer():
            self._dispatch_messages(msg)

    def send(self, message: qrllegacy_pb2.LegacyMessage):
        self.transport.write(self._wrap_message(message))

    def loseConnection(self):
        self.transport.loseConnection()

    ###################################################
    ###################################################
    ###################################################
    ###################################################
    # Low-level serialization/connections/etc
    # FIXME: This is a temporary refactoring, it will be completely replaced before release
    def _dispatch_messages(self, message: qrllegacy_pb2.LegacyMessage):
        func = self._services.get(message.func_name)
        if func:
            try:
                # FIXME: use WhichOneof to discover payloads
                func(message)
            except Exception as e:
                logger.debug("executing [%s] by %s", message.func_name, self._conn_identity)
                logger.exception(e)

    @staticmethod
    def _wrap_message(protobuf_obj) -> bytes:
        """
        Receives a protobuf object and encodes it as (length)(data)
        :return: the encoded message
        :rtype: bytes
        >>> veData = qrllegacy_pb2.VEData(version="version", genesis_prev_hash=b'genesis_hash')
        >>> msg = qrllegacy_pb2.LegacyMessage(func_name=qrllegacy_pb2.LegacyMessage.VE, veData=veData)
        >>> bin2hstr(P2PProtocol._wrap_message(msg))
        '000000191a170a0776657273696f6e120c67656e657369735f68617368'
        """
        # FIXME: This is not the final implementation, it is just a workaround for refactoring
        # FIXME: struct.pack may result in endianness problems
        # NOTE: This temporary approach does not allow for alignment. Once the stream is off, it will need to clear
        data = protobuf_obj.SerializeToString()
        str_data_len = struct.pack('>L', len(data))
        return str_data_len + data

    def _parse_buffer(self):
        # FIXME: This parsing/wire protocol needs to be replaced
        """
        >>> from pyqrllib.pyqrllib import hstr2bin
        >>> p=P2PProtocol()
        >>> p._buffer = bytes(hstr2bin('000000191a170a0776657273696f6e120c67656e657369735f68617368'+ \
                                       '000000191a170a0776657273696f6e120c67656e657369735f68617368'))
        >>> messages = p._parse_buffer()
        >>> len(list(messages))
        2
        """
        while self._buffer:
            # FIXME: This is not the final implementation, it is just a minimal implementation for refactoring
            if len(self._buffer) < 4:
                # Buffer is still incomplete as it doesn't have message size
                return

            chunk_size_raw = self._buffer[:4]
            chunk_size = struct.unpack('>L', chunk_size_raw)[0]  # is m length encoded correctly?

            # FIXME: There is no limitation on the buffer size or timeout
            if len(self._buffer) < chunk_size:
                # Buffer is still incomplete as it doesn't have message
                if chunk_size_raw[0] == 0xff:
                    # FIXME: Remove this. Workaround for old protocol
                    self.transport.loseConnection()
                return

            try:
                message_raw = self._buffer[4:4 + chunk_size]
                message = qrllegacy_pb2.LegacyMessage()
                message.ParseFromString(message_raw)
                yield message
            except Exception as e:
                logger.warning("Problem parsing message. Skipping")
            finally:
                self._buffer = self._buffer[4 + chunk_size:]
