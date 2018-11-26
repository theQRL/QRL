from pyqryptonight.pyqryptonight import PoWHelper

from qrl.core import config


class DifficultyTracker(object):
    """
    State.get_measurement calculates whether the last few blocks were found
    earlier/later than expected. This measurement is then passed down to
    DifficultyTracker, which calculates what the next difficulty/target should
    be.

    These simple functions don't need to be a class, but they are useful in
    Miner and ChainManager (potential for cyclic dependencies), and it's nice to
    have this PoW related code boxed away so that the move to PoS will be
    easier.
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
