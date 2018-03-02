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

        new_diff, new_target = DifficultyTracker.get(
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

        expected_blob = tuple([241, 93, 178, 239, 171, 183, 27, 87, 2,
                               191, 178, 157, 32, 74, 254, 207, 242, 82, 128,
                               197, 58, 86, 24, 90, 106, 33, 58, 82, 160,
                               251, 118, 174, 45, 182, 72, 157, 142, 141,
                               219, 0, 0, 0, 15, 61, 11, 20, 166, 132, 14,
                               29, 248, 65, 55, 56, 226, 12, 57, 60, 37, 64,
                               123, 44, 48, 172, 218, 221, 26, 8, 143, 110,
                               38, 215, 83, 248, 227, 87, 148, 88, 237, 48,
                               203, 111, 245, 31, 125, 45, 14, 111, 109, 0,
                               87, 13, 154, 252, 49, 160])

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
        self.assertTrue(PoWHelper().verifyInput(custom_qminer.solution_blob, new_target))
