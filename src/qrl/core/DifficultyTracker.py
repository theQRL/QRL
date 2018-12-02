from pyqryptonight.pyqryptonight import PoWHelper

from qrl.core import config


class DifficultyTracker(object):
    """
    DifficultyTracker calculates what the next difficulty/target should be,
    given when the last few blocks were produced. This information is provided
    by State.get_measurement().

    get_target() vs get(): target and difficulty are two sides of the same coin
    - the target is the value which the hash has to be less than, and the lower
    the target, the higher the difficulty.
    """

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
