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
        block_header = BlockHeader.create(1, sha256(b'prev'), sha256(b'txs'), 10)
        self.assertIsNotNone(block_header)  # just to avoid warnings

    def test_blob(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948

            block_header = BlockHeader.create(1, sha256(b'prev'), sha256(b'txs'), 10)
            self.assertEquals('74aa496ffe19107faaf418b720fb5b8446ba4b595c178fcf099c99b3dee99860d788c77910a9ed000000'
                              '000000000000000000e0d022b37421b81b7bbcf5b497fb89408c05c7d713c5e1e5187b02aa9344cf83bb',
                              bin2hstr(block_header.mining_blob))
            self.assertEquals(config.dev.mining_blob_size, len(block_header.mining_blob))

    def test_hash(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948

            block_header = BlockHeader.create(1, sha256(b'prev'), sha256(b'txs'), 10)
            header_hash = block_header.generate_headerhash()

            self.assertEquals('584f898a54269d0651cca3403843d4cdb764e5a31655bf51db39bbf8c4883b01',
                              bin2hstr(header_hash))

            self.assertEquals(bin2hstr(header_hash),
                              bin2hstr(block_header.headerhash))

            self.assertEquals(32, len(block_header.headerhash))

    def test_hash_nonce(self):
        with mock.patch('qrl.core.misc.ntp.getTime') as time_mock:
            time_mock.return_value = 1615270948

            block_header = BlockHeader.create(1, sha256(b'prev'), sha256(b'txs'), 10)

            block_header.set_nonces(100, 0)

            header_hash = block_header.generate_headerhash()

            self.assertEquals('28556460d0b3b4830ef3d74fab1cd52bca25ee00d1a6396a7f053d53549f73ba',
                              bin2hstr(header_hash))

            self.assertEquals(bin2hstr(header_hash),
                              bin2hstr(block_header.headerhash))

            self.assertEquals(32, len(block_header.headerhash))
