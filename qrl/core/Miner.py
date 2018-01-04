# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from twisted.internet import reactor
from pyqryptonight.pyqryptonight import Qryptominer

from qrl.core import config
from qrl.core.misc import logger


class CustomQMiner(Qryptominer):
    def __init__(self, callback):
        Qryptominer.__init__(self)
        self.callback_fn = callback
        self.callLater_fn = None

    def solutionEvent(self, nonce):
        logger.debug('Solution Found %s', nonce)
        try:
            self.callLater_fn.cancel()
        except Exception:
            pass
        self.callLater_fn = reactor.callLater(0, self.callback_fn, nonce)


class Miner:
    def __init__(self, create_next_block):
        self.custom_qminer = CustomQMiner(self.mined)
        self.create_next_block = create_next_block

    def start_mining(self, input_bytes, nonce_offset, current_target, thread_count=config.user.mining_thread_count):
        self.custom_qminer.setInput(input=input_bytes,
                                    nonceOffset=nonce_offset,
                                    target=current_target)
        self.custom_qminer.start(thread_count=thread_count)

    def mined(self, nonce):
        self.create_next_block(mining_nonce=nonce)

    def cancel(self):
        self.custom_qminer.cancel()
