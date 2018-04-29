# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.BlockHeader import BlockHeader
from qrl.crypto.misc import sha256

logger.initialize_default()


class TestBlockHeader(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBlockHeader, self).__init__(*args, **kwargs)

    def test_init(self):
        block_header = BlockHeader()
        self.assertIsNotNone(block_header)  # just to avoid warnings

    def test_init2(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948
            block_header = BlockHeader.create(1, sha256(b'prev'), time_mock.return_value, sha256(b'txs'), 10)
            self.assertIsNotNone(block_header)  # just to avoid warnings

    def test_blob(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948

            block_header = BlockHeader.create(1, sha256(b'prev'), time_mock.return_value, sha256(b'txs'), 10)
            self.assertEquals('00501846b24200c31fca7172a7f701ae50322579cfdf1d7777daab4ce6ead70b76debb2c51a1'
                              'c70000000000000000000000002b80aecec05ad5c7c4f2259c8f69e2966a6ce102d4609af2cd',
                              bin2hstr(block_header.mining_blob))
            self.assertEquals(config.dev.mining_blob_size, len(block_header.mining_blob))

    def test_hash(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948

            block_header = BlockHeader.create(1, sha256(b'prev'), time_mock.return_value, sha256(b'txs'), 10)
            header_hash = block_header.generate_headerhash()

            self.assertEquals('81dd8032691331fb9cb6d4b8c3cf82dfec7873eb96789a10076b70da45315a38',
                              bin2hstr(header_hash))

            self.assertEquals(bin2hstr(header_hash),
                              bin2hstr(block_header.headerhash))

            self.assertEquals(32, len(block_header.headerhash))

    def test_hash_nonce(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948

            block_header = BlockHeader.create(1, sha256(b'prev'), time_mock.return_value, sha256(b'txs'), 10)

            block_header.set_nonces(100, 0)

            header_hash = block_header.generate_headerhash()

            self.assertEquals('f48ef2a482b2b85b429979ea1d7014806754b3ff37705c4f61a54f17bca4ccc4',
                              bin2hstr(header_hash))

            self.assertEquals(bin2hstr(header_hash),
                              bin2hstr(block_header.headerhash))

            self.assertEquals(32, len(block_header.headerhash))
