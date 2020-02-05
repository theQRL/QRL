# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core import config
from qrl.core.Singleton import Singleton
from qrl.core.miners.qryptonight7.CNv1PoWValidator import CNv1PoWValidator
from qrl.core.miners.qrandomx.QRXPoWValidator import QRXPoWValidator


class PoWValidator(object, metaclass=Singleton):
    def __init__(self):
        self.qryptonight_7_pow_validator = CNv1PoWValidator()
        self.qryptonight_r_pow_validator = QRXPoWValidator()

    def verify_input(self, block_number, seed_height, seed_hash, mining_blob, target):
        if block_number < config.dev.hard_fork_heights[0]:
            return self.qryptonight_7_pow_validator.verify_input(mining_blob, target)
        else:
            return self.qryptonight_r_pow_validator.verify_input(block_number,
                                                                 seed_height,
                                                                 seed_hash,
                                                                 mining_blob,
                                                                 target)
