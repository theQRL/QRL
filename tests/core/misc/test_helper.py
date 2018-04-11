# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from ipaddress import AddressValueError
from unittest import TestCase

from qrl.core.misc import logger
from qrl.core.misc.helper import parse_peer_addr

logger.initialize_default()


class TestHelper(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHelper, self).__init__(*args, **kwargs)

    def test_basic_1(self):
        ip, port = parse_peer_addr('192.168.0.1:10000')
        self.assertEquals('192.168.0.1', ip)
        self.assertEquals(10000, port)

    def test_basic_2(self):
        ip, port = parse_peer_addr('192.168.0.1:1234')
        self.assertEquals('192.168.0.1', ip)
        self.assertEquals(1234, port)

    def test_basic_3(self):
        ip, port = parse_peer_addr('192.168.0.1')
        self.assertEquals('192.168.0.1', ip)
        self.assertEquals(9000, port)

    def test_invalid_1(self):
        with self.assertRaisesRegexp(AddressValueError, 'Address cannot be empty'):
            parse_peer_addr('')

    def test_invalid_2(self):
        with self.assertRaisesRegexp(AddressValueError, 'Expected 4 octets in \'abc\''):
            parse_peer_addr('abc')

    def test_wrong_port_1(self):
        with self.assertRaisesRegexp(ValueError, 'Invalid Peer Port 192.168.0.1:100000'):
            parse_peer_addr('192.168.0.1:100000')

    def test_wrong_port_2(self):
        with self.assertRaisesRegexp(ValueError, 'Invalid Peer Port 192.168.0.1:A'):
            parse_peer_addr('192.168.0.1:A')

    def test_wrong_port_3(self):
        with self.assertRaisesRegexp(ValueError, 'Invalid Peer Port 192.168.0.1:-1'):
            parse_peer_addr('192.168.0.1:-1')

    def test_global_1(self):
        with self.assertRaisesRegexp(ValueError, 'Local Peer IP Found 192.168.0.1:9000'):
            parse_peer_addr('192.168.0.1:9000', check_global=True)

    def test_global_2(self):
        ip, port = parse_peer_addr('123.123.123.1:9000', check_global=True)
        self.assertEquals('123.123.123.1', ip)
        self.assertEquals(9000, port)
