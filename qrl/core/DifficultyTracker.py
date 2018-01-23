from typing import List

from pyqryptonight.pyqryptonight import PoWHelper


class DifficultyTracker(object):
    def __init__(self):
        self.ph = PoWHelper(kp=100,
                            set_point=60)

    def get(self,
            timestamp,
            previous_timestamps: List,
            parent_difficulty):
        self.ph.clearTimestamps()
        for t in previous_timestamps:
            self.ph.addTimestamp(t)

        current_difficulty = self.ph.getDifficulty(timestamp=timestamp,
                                                   parent_difficulty=parent_difficulty)

        current_target = self.ph.getBoundary(current_difficulty)
        return current_difficulty, current_target
