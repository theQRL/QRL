# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import threading
from unittest import TestCase

from pyqryptonight.pyqryptonight import Qryptominer, PoWHelper

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
        self.assertEqual(tuple(block.mining_hash), (
            186, 155, 236, 133, 247, 194, 196, 56,
            208, 139, 175, 190, 149, 30, 119, 56,
            146, 137, 223, 27, 167, 199, 76, 131,
            237, 152, 160, 251, 168, 78, 77, 181))

        input_bytes = [0, 0, 0, 6, 186, 155, 236, 133,
                       247, 194, 196, 56, 208, 139, 175,
                       190, 149, 30, 119, 56, 146, 137, 223,
                       27, 167, 199, 76, 131, 237, 152,
                       160, 251, 168, 78, 77, 181]

        custom_qminer = CustomQMiner()
        custom_qminer.start(input=input_bytes,
                            nonceOffset=0,
                            target=new_target,
                            thread_count=2)
        custom_qminer.wait_for_solution()

        print(custom_qminer.nonce)
        self.assertTrue(PoWHelper.verifyInput(input_bytes, new_target))
