from pyqryptonight.pyqryptonight import PoWHelper

from qrl.core import config


class DifficultyTracker(object):
    def __init__(self):
        pass

    def get_kp(self, block_idx):
        if block_idx < 5000:
            return 100

        return 5

    def get(self,
            block_idx,
            measurement,
            parent_difficulty):
        kp = self.get_kp(block_idx)

        ph = PoWHelper(kp=kp,
                       set_point=config.dev.mining_setpoint_blocktime)

        current_difficulty = ph.getDifficulty(measurement=measurement,
                                              parent_difficulty=parent_difficulty)

        current_target = ph.getBoundary(current_difficulty)
        return current_difficulty, current_target
