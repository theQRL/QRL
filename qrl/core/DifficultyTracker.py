from pyqryptonight.pyqryptonight import PoWHelper

from qrl.core import config


class DifficultyTracker(object):
    def __init__(self):
        self.ph = PoWHelper(kp=100,
                            set_point=config.dev.mining_setpoint_blocktime)

    def get(self,
            measurement,
            parent_difficulty):
        current_difficulty = self.ph.getDifficulty(measurement=measurement,
                                                   parent_difficulty=parent_difficulty)

        current_target = self.ph.getBoundary(current_difficulty)
        return current_difficulty, current_target
