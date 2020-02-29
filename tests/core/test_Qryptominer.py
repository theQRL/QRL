# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading
from unittest import TestCase

from pyqryptonight.pyqryptonight import Qryptominer, PoWHelper, SOLUTION

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.Block import Block
from qrl.core.DifficultyTracker import DifficultyTracker
from tests.misc.helper import read_data_file

logger.initialize_default()


class TestQryptominer(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestQryptominer, self).__init__(*args, **kwargs)

    def test_verify(self):

        class CustomQMiner(Qryptominer):
            def __init__(self):
                Qryptominer.__init__(self)
                self._solution_lock = threading.Lock()
                self.nonce = None
                self.solution_blob = None

            def start(self, input, nonceOffset, target, thread_count=1):
                self.cancel()
                try:
                    self._solution_lock.release()
                except RuntimeError:
                    pass
                self._solution_lock.acquire(blocking=False)
                super().start(input, nonceOffset, target, thread_count)

            def wait_for_solution(self):
                self._solution_lock.acquire(blocking=True)
                self._solution_lock.release()

            def handleEvent(self, event):
                if event.type == SOLUTION:
                    self.nonce = event.nonce
                    self.solution_blob = self.solutionInput()
                    self._solution_lock.release()

        block_timestamp = 1515443508
        parent_block_timestamp = 1515443508

        # This could be the average of last N blocks
        measurement = block_timestamp - parent_block_timestamp

        parent_difficulty = (0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 4)

        new_diff, new_target = DifficultyTracker.get(
            measurement,
            parent_difficulty=parent_difficulty,
            dev_config=config.dev)

        self.assertEqual(new_diff, (0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 5))

        self.assertEqual(new_target, (
            51, 51, 51, 51, 51, 51, 51, 51,
            51, 51, 51, 51, 51, 51, 51, 51,
            51, 51, 51, 51, 51, 51, 51, 51,
            51, 51, 51, 51, 51, 51, 51, 51))

        block_json = read_data_file('core/example_block_mining.json')

        block = Block.from_json(block_json)

        expected_blob = (0, 231, 90, 101, 142, 20, 245, 183, 96, 5, 216, 159, 111, 239, 93, 217, 138, 10, 227, 159, 198,
                         207, 109, 238, 83, 220, 167, 148, 247, 200, 197, 41, 37, 36, 150, 12, 116, 85, 254, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 181, 198, 40, 62, 106, 139, 108, 83, 216, 206, 161, 148,
                         50, 65, 212, 137, 94, 102, 124, 45)
        self.assertEqual(expected_blob, tuple(block.mining_blob(dev_config=config.dev)))

        custom_qminer = CustomQMiner()
        custom_qminer.start(input=block.mining_blob(dev_config=config.dev),
                            nonceOffset=block.mining_nonce_offset(dev_config=config.dev),
                            target=new_target,
                            thread_count=2)
        custom_qminer.wait_for_solution()

        expected_mined_blob = bytearray(expected_blob)
        tmp_offset = config.dev.mining_nonce_offset
        expected_mined_blob[tmp_offset:tmp_offset + 4] = custom_qminer.nonce.to_bytes(4,
                                                                                      byteorder='big',
                                                                                      signed=False)

        print(custom_qminer.nonce)
        self.assertEqual(tuple(expected_mined_blob), custom_qminer.solution_blob)
        self.assertTrue(PoWHelper().verifyInput(custom_qminer.solution_blob, new_target))
