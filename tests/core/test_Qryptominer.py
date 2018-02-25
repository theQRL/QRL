# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading
from unittest import TestCase

from pyqryptonight.pyqryptonight import Qryptominer, PoWHelper

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.DifficultyTracker import DifficultyTracker
from tests.misc.helper import read_data_file


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

            def start(self, input, nonceOffset, target, thread_count):
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

            def solutionEvent(self, nonce):
                print('Solution Found %s', nonce)
                self.nonce = nonce
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

        diff_tracker = DifficultyTracker()

        new_diff, new_target = diff_tracker.get(
            measurement,
            parent_difficulty=parent_difficulty)

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

        expected_blob = tuple([0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0, 0, 90, 83,
                               213, 52, 38, 244, 141, 56, 25, 77, 68, 132,
                               105, 218, 205, 252, 195, 146, 179, 71, 161,
                               233, 20, 102, 4, 184, 120,
                               0, 0, 0, 15,
                               112, 216, 21, 183, 15, 54, 163, 1, 178,
                               0, 0, 0, 0, 27, 125, 126, 51, 0, 0, 0, 0, 0,
                               0, 0, 0, 227, 176, 196, 66, 152, 252, 28, 20,
                               154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
                               65, 228, 100, 155, 147, 76, 164, 149, 153, 27,
                               120, 82, 184, 85, 40, 109, 44, 184, 105, 46,
                               28, 134, 239, 96, 70, 82, 177, 18, 248, 204, 58,
                               55, 137, 158, 95, 115, 126, 227, 177, 1, 203,
                               182, 93, 123, 218, 65, 142, 139, 172, 33, 29,
                               225, 2, 207, 95, 249, 12, 28, 107, 140, 4, 196,
                               135, 162, 255, 196, 26, 250, 53, 123, 92, 194,
                               52, 53, 97, 170, 105, 140])

        self.assertEqual(expected_blob, tuple(block.mining_blob))

        custom_qminer = CustomQMiner()
        custom_qminer.start(input=block.mining_blob,
                            nonceOffset=block.mining_nonce_offset,
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
        self.assertTrue(PoWHelper.verifyInput(custom_qminer.solution_blob, new_target))
