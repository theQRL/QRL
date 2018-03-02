# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import contextlib
from unittest import TestCase

from qrl.core import config
from qrl.core.misc import logger
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from tests.blockchain.MockedBlockchain import MockedBlockchain

logger.initialize_default()


@contextlib.contextmanager
def set_timeseries_size(new_size):
    old_value = config.dev.block_timeseries_size
    try:
        config.dev.block_timeseries_size = new_size
        yield
    finally:
        config.dev.block_timeseries_size = old_value


class TestPublicAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI, self).__init__(*args, **kwargs)

    def test_getStats(self):
        number_blocks = 1
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            with set_timeseries_size(10):
                service = PublicAPIService(mock_blockchain.qrlnode)

                for i in range(number_blocks + 1, 50):
                    mock_blockchain.add_new_block()

                    request = qrl_pb2.GetStatsReq()
                    request.include_timeseries = True

                    stats = service.GetStats(request=request, context=None)

                    self.assertEqual(min(10, i + 1), len(stats.block_timeseries))

    def getStats_forking(self, timeseries_size):
        number_blocks = 10
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            with set_timeseries_size(timeseries_size):
                service = PublicAPIService(mock_blockchain.qrlnode)

                request = qrl_pb2.GetStatsReq(include_timeseries=True)
                stats = service.GetStats(request=request, context=None)
                self.assertEqual(timeseries_size, len(stats.block_timeseries))

                # Fork at node 9 with 2 blocks (b)
                block_9 = mock_blockchain.qrlnode.get_block_from_index(9)
                block_10 = mock_blockchain.qrlnode.get_block_last()
                block_10b = mock_blockchain.create_block(block_9.headerhash)
                mock_blockchain.add_block(block_10b)
                block_11b = mock_blockchain.create_block(block_10b.headerhash)
                mock_blockchain.add_block(block_11b)

                # Get time series
                request = qrl_pb2.GetStatsReq(include_timeseries=True)
                stats = service.GetStats(request=request, context=None)
                self.assertEqual(timeseries_size, len(stats.block_timeseries))

                # check stats have moved to the correct branch
                self.assertEqual(block_11b.headerhash, stats.block_timeseries[-1].header_hash)

                # Add back to the original chain (a)
                block_11 = mock_blockchain.create_block(block_10.headerhash)
                mock_blockchain.add_block(block_11)
                block_12 = mock_blockchain.create_block(block_11.headerhash)
                mock_blockchain.add_block(block_12)

                # Get time series
                request = qrl_pb2.GetStatsReq(include_timeseries=True)
                stats = service.GetStats(request=request, context=None)
                self.assertEqual(timeseries_size, len(stats.block_timeseries))
                # check stats have moved back to the correct branch
                self.assertEqual(block_12.headerhash, stats.block_timeseries[-1].header_hash)

    def test_getStats_forking1(self):
        # FIXME: Parametrized testing is different in nose/pytest and that brings incompatibilities
        self.getStats_forking(timeseries_size=1)

    def test_getStats_forking5(self):
        self.getStats_forking(timeseries_size=5)

    def test_getStats_forking10(self):
        self.getStats_forking(timeseries_size=10)
