from ipaddress import IPv4Address

from qrl.core import config


class IPMetadata(object):
    def __init__(self, ip_str: str, port: int):
        self._ip = ip_str

        try:
            self._port = int(port)
        except ValueError:
            raise ValueError('Invalid Peer Port {}'.format(port))

        self.ip_address = IPv4Address(self._ip)

        if not (0 < self._port <= 65535):  # Validate port number
            raise ValueError('Invalid Peer Port {}'.format(self))

    def __repr__(self):
        return self.full_address

    def __hash__(self):
        return hash(self.__repr__())

    def __eq__(self, other):
        if isinstance(other, IPMetadata):
            return self._ip == other._ip and self._port == other._port
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def _validate(self):
        pass

    @property
    def full_address(self):
        return "{}:{}".format(self.ip, self.port)

    @property
    def ip(self):
        return self._ip

    @property
    def port(self):
        return self._port

    @property
    def is_global(self):
        return self.ip_address.is_global

    @classmethod
    def from_full_address(cls, full_address: str, check_global=False):
        parts = full_address.split(':')

        ip = parts[0]
        port = config.user.p2p_local_port
        if check_global:
            port = config.user.p2p_public_port

        if len(parts) > 2:
            raise ValueError('Invalid Peer address')

        if len(parts) == 2:
            try:
                port = int(parts[1])
            except ValueError as e:
                raise ValueError('Invalid Peer Port {} - {}'.format(full_address, str(e)))

        answer = cls(ip, port)
        if check_global:
            if not answer.is_global:  # Check for Global IP
                raise ValueError('Local Peer IP Found {}'.format(full_address))

        return answer

    @staticmethod
    def canonical_full_address(full_address: str, check_global=False):
        return IPMetadata.from_full_address(full_address, check_global).full_address
