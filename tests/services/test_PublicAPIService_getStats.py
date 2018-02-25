# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from tests.misc.helper import qrlnode_with_mock_blockchain

logger.initialize_default()


class TestPublicAPI2(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI2, self).__init__(*args, **kwargs)

    def test_getStats2(self):
        number_blocks = 50
        with qrlnode_with_mock_blockchain(number_blocks) as qrlnode:
            service = PublicAPIService(qrlnode)
            request = qrl_pb2.GetStatsReq()
            request.include_timeseries = True

            stats = service.GetStats(request=request, context=None)
            self.assertEqual(number_blocks, len(stats.block_timeseries))
            logger.info(stats)
