# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from decimal import Decimal
from mock import mock

import qrl
from qrl.core import config
from qrl.core.misc import logger
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from tests.misc.MockedBlockchain import MockedBlockchain

logger.initialize_default()


class TestPublicAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestPublicAPI, self).__init__(*args, **kwargs)

    def test_getStats2(self):
        number_blocks = 1
        with MockedBlockchain.create(number_blocks) as mock_blockchain:
            service = PublicAPIService(mock_blockchain.qrlnode)
            default_value = qrl.core.config.dev.block_timeseries_size

            try:
                qrl.core.config.dev.block_timeseries_size = 10

                for i in range(number_blocks + 1, 50):
                    mock_blockchain.add_new_block()

                    request = qrl_pb2.GetStatsReq()
                    request.include_timeseries = True

                    stats = service.GetStats(request=request, context=None)

                    self.assertEqual(min(10, i + 1), len(stats.block_timeseries))

            finally:
                qrl.core.config.dev.block_timeseries_size = default_value
