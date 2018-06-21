# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from ipaddress import AddressValueError
from unittest import TestCase

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.p2p.IPMetadata import IPMetadata

logger.initialize_default()


class TestHelper(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHelper, self).__init__(*args, **kwargs)

    def test_basic_1(self):
        addr = IPMetadata.from_full_address('192.168.0.1:10000')
        self.assertEquals('192.168.0.1', addr.ip)
        self.assertEquals(10000, addr.port)

    def test_basic_2(self):
        addr = IPMetadata.from_full_address('192.168.0.1:1234')
        self.assertEquals('192.168.0.1', addr.ip)
        self.assertEquals(1234, addr.port)

    def test_basic_3(self):
        addr = IPMetadata.from_full_address('192.168.0.1')
        self.assertEquals('192.168.0.1', addr.ip)
        self.assertEquals(config.user.p2p_local_port, addr.port)

    def test_invalid_1(self):
        with self.assertRaisesRegexp(AddressValueError, 'Address cannot be empty'):
            IPMetadata.from_full_address('')

    def test_invalid_2(self):
        with self.assertRaisesRegexp(AddressValueError, 'Expected 4 octets in \'abc\''):
            IPMetadata.from_full_address('abc')

    def test_wrong_port_1(self):
        with self.assertRaisesRegexp(ValueError, 'Invalid Peer Port 192.168.0.1:100000'):
            IPMetadata.from_full_address('192.168.0.1:100000')

    def test_wrong_port_2(self):
        with self.assertRaisesRegexp(ValueError, 'Invalid Peer Port 192.168.0.1:A'):
            IPMetadata.from_full_address('192.168.0.1:A')

    def test_wrong_port_3(self):
        with self.assertRaisesRegexp(ValueError, 'Invalid Peer Port 192.168.0.1:-1'):
            IPMetadata.from_full_address('192.168.0.1:-1')

    def test_global_1(self):
        with self.assertRaisesRegexp(ValueError, 'Local Peer IP Found 192.168.0.1:9000'):
            IPMetadata.from_full_address('192.168.0.1:9000', check_global=True)

    def test_global_2(self):
        addr = IPMetadata.from_full_address('123.123.123.1:9000', check_global=True)
        self.assertEquals('123.123.123.1', addr.ip)
        self.assertEquals(9000, addr.port)
