from pyqryptonight.pyqryptonight import PoWHelper


class DifficultyTracker(object):
    def __init__(self):
        pass

    @staticmethod
    def get_target(current_difficulty, dev_config):
        ph = PoWHelper(kp=dev_config.kp,
                       set_point=dev_config.block_timing_in_seconds)
        return ph.getTarget(current_difficulty)

    @staticmethod
    def get(measurement, parent_difficulty, dev_config):
        ph = PoWHelper(kp=dev_config.kp,
                       set_point=dev_config.block_timing_in_seconds)

        current_difficulty = ph.getDifficulty(measurement=measurement,
                                              parent_difficulty=parent_difficulty)

        current_target = ph.getTarget(current_difficulty)
        return current_difficulty, current_target
