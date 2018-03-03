from pyqryptonight.pyqryptonight import PoWHelper

from qrl.core import config


class DifficultyTracker(object):
    def __init__(self):
        pass

    @staticmethod
    def get_target(current_difficulty):
        ph = PoWHelper(kp=config.dev.kp,
                       set_point=config.dev.mining_setpoint_blocktime)
        return ph.getTarget(current_difficulty)

    @staticmethod
    def get(measurement,
            parent_difficulty):

        ph = PoWHelper(kp=config.dev.kp,
                       set_point=config.dev.mining_setpoint_blocktime)

        current_difficulty = ph.getDifficulty(measurement=measurement,
                                              parent_difficulty=parent_difficulty)

        current_target = ph.getTarget(current_difficulty)
        return current_difficulty, current_target
