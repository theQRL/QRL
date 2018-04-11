# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from ipaddress import IPv4Address

from qrl.core import config


def parse_peer_addr(s: str, check_global: bool = False) -> [str, int]:
    parts = s.split(':')

    ip = parts[0]
    port = config.user.p2p_local_port
    if check_global:
        port = config.user.p2p_public_port

    if len(parts) > 2:
        raise ValueError('Invalid Peer address')
    elif len(parts) == 2:
        try:
            port = int(parts[1])
        except ValueError as e:
            raise ValueError('Invalid Peer Port {} - {}'.format(s, str(e)))

        if not (0 < port <= 65535):  # Validate port number
            raise ValueError('Invalid Peer Port {}'.format(s))

    # Validate ip address
    ip_address = IPv4Address(ip)

    if check_global:
        if not ip_address.is_global:  # Check for Global IP
            raise ValueError('Local Peer IP Found {}'.format(s))

    return ip, port
