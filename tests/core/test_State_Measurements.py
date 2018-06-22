# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock, mock

from qrl.core import config
from qrl.core.State import State
from qrl.core.misc import logger
from tests.misc.helper import set_qrl_dir

logger.initialize_default()


class TestStateMeasurement(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestStateMeasurement, self).__init__(*args, **kwargs)

    @staticmethod
    def get_block_list_example1():
        block1 = Mock()
        block1.block_number = 0
        block1.timestamp = 10
        block1.headerhash = b'0'
        block1.prev_headerhash = b'99999'

        block2 = Mock()
        block2.block_number = 1
        block2.timestamp = 160
        block2.headerhash = b'1'
        block2.prev_headerhash = b'0'

        block3 = Mock()
        block3.block_number = 2
        block3.timestamp = 230
        block3.headerhash = b'2'
        block3.prev_headerhash = b'1'

        block4 = Mock()
        block4.block_number = 3
        block4.timestamp = 310
        block4.headerhash = b'3'
        block4.prev_headerhash = b'2'

        return [
            block1,
            block2,
            block3,
            block4
        ]

    @staticmethod
    def get_block_example1(header_hash):
        block_list = TestStateMeasurement.get_block_list_example1()
        for b in block_list:
            if b.headerhash == header_hash:
                return b
        return None

    def test_check_mock(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

                state.get_block = Mock()

                state.get_block.side_effect = self.get_block_list_example1()

                block = state.get_block(b'0')

                self.assertEqual(10, block.timestamp)
                self.assertEqual(0, block.block_number)
                self.assertEqual(b'0', block.headerhash)

    def test_check_mock_get(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)

                state.get_block = Mock(side_effect=TestStateMeasurement.get_block_example1)

                block = state.get_block(b'1')
                self.assertEqual(1, block.block_number)
                self.assertEqual(160, block.timestamp)

                block = state.get_block(b'3')
                self.assertEqual(3, block.block_number)
                self.assertEqual(310, block.timestamp)

                block = state.get_block(b'0')
                self.assertEqual(0, block.block_number)
                self.assertEqual(10, block.timestamp)

    def test_measurement_0(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)
                state.get_block = Mock(side_effect=TestStateMeasurement.get_block_example1)
                parent_metadata = Mock()
                parent_metadata.last_N_headerhashes = []

                measurement = state.get_measurement(100, parent_headerhash=b'0', parent_metadata=parent_metadata)
                self.assertEqual(60, measurement)

                measurement = state.get_measurement(110, parent_headerhash=b'0', parent_metadata=parent_metadata)
                self.assertEqual(60, measurement)

                measurement = state.get_measurement(1000, parent_headerhash=b'0', parent_metadata=parent_metadata)
                self.assertEqual(60, measurement)

    def test_measurement_1(self):
        with set_qrl_dir('no_data'):
            with State() as state:
                self.assertIsNotNone(state)  # to avoid warning (unused variable)
                state.get_block = Mock(side_effect=TestStateMeasurement.get_block_example1)
                parent_metadata = Mock()
                parent_metadata.last_N_headerhashes = [b'0']

                measurement = state.get_measurement(210, b'1', parent_metadata)
                self.assertEqual(55, measurement)

                measurement = state.get_measurement(250, b'1', parent_metadata)
                self.assertEqual(75, measurement)

    def test_measurement_3(self):
        db_name = config.dev.db_name
        with mock.patch('qrl.core.config.dev') as devconfig:
            devconfig.N_measurement = 2
            devconfig.db_name = db_name
            with set_qrl_dir('no_data'):
                with State() as state:
                    self.assertIsNotNone(state)  # to avoid warning (unused variable)
                    state.get_block = Mock(side_effect=TestStateMeasurement.get_block_example1)
                    parent_metadata = Mock()
                    parent_metadata.last_N_headerhashes = [b'1', b'2']

                    measurement = state.get_measurement(350, b'3', parent_metadata)
                    self.assertEqual(60, measurement)

                    measurement = state.get_measurement(370, b'3', parent_metadata)
                    self.assertEqual(70, measurement)

    def test_measurement_4(self):
        db_name = config.dev.db_name
        with mock.patch('qrl.core.config.dev') as devconfig:
            devconfig.N_measurement = 3
            devconfig.db_name = db_name
            with set_qrl_dir('no_data'):
                with State() as state:
                    self.assertIsNotNone(state)  # to avoid warning (unused variable)
                    state.get_block = Mock(side_effect=TestStateMeasurement.get_block_example1)
                    parent_metadata = Mock()
                    parent_metadata.last_N_headerhashes = [b'0', b'1', b'2']

                    measurement = state.get_measurement(350, b'3', parent_metadata)
                    self.assertEqual(63, measurement)

                    measurement = state.get_measurement(370, b'3', parent_metadata)
                    self.assertEqual(70, measurement)
