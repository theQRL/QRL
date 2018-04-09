# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from ipaddress import IPv4Address


def parse_peer_addr(s: str, check_global: bool=False) -> [str, int]:
    parts = s.split(':')
    ip = parts[0]
    if len(parts) == 2:
        port = int(parts[1])
    if len(parts) == 1:
        port = 9000

    if not (0 < port <= 65535):  # Validate port number
        raise ValueError('Invalid Peer Port %s', s)

    if check_global:
        if not IPv4Address(ip).is_global:  # Check for Global IP
            raise ValueError('Local Peer IP Found %s', s)

    return ip, port
