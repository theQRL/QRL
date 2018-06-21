# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict

from pyqrllib.pyqrllib import bin2hstr
from twisted.internet import reactor

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.ESyncState import ESyncState
from qrl.core.Miner import Miner
from qrl.core.misc import ntp, logger


class SyncState:
    def __init__(self):
        self.state = ESyncState.unsynced
        self.epoch_diff = -1


class ConsensusMechanism(object):
    def __init__(self,
                 chain_manager: ChainManager):
        self.chain_manager = chain_manager


class POW(ConsensusMechanism):
    def __init__(self,
                 chain_manager: ChainManager,
                 p2p_factory,
                 sync_state: SyncState,
                 time_provider,
                 mining_address: bytes,
                 mining_thread_count):

        super().__init__(chain_manager)
        self.sync_state = sync_state
        self.time_provider = time_provider

        self.miner_toggler = False
        self.mining_address = mining_address

        self.p2p_factory = p2p_factory  # FIXME: Decouple from p2pFactory. Comms vs node logic
        self.p2p_factory.pow = self  # FIXME: Temporary hack to keep things working while refactoring

        self.miner = Miner(self.pre_block_logic,
                           self.mining_address,
                           self.chain_manager,
                           mining_thread_count,
                           self.p2p_factory.add_unprocessed_txn)

        ########

        self.last_pow_cycle = 0
        self.last_bk_time = 0
        self.last_pb_time = 0
        self.suspend_mining_timestamp = 0

        self.future_blocks = OrderedDict()  # Keeps the list of future blocks, which has to be processed later

        self.epoch_diff = None

    ##################################################
    ##################################################
    ##################################################
    ##################################################

    def start(self):
        self.restart_monitor_bk(80)
        reactor.callLater(1, self.initialize_pow)

    def _handler_state_unsynced(self):
        self.miner.cancel()
        self.last_bk_time = ntp.getTime()
        self.restart_unsynced_logic()

    def _handler_state_syncing(self):
        self.last_pb_time = ntp.getTime()

    def _handler_state_synced(self):
        self.last_pow_cycle = ntp.getTime()
        last_block = self.chain_manager.last_block
        self._mine_next(last_block)

    def _handler_state_forked(self):
        pass

    def update_node_state(self, new_sync_state: ESyncState):
        self.sync_state.state = new_sync_state
        logger.info('Status changed to %s', self.sync_state.state)

        _mapping = {
            ESyncState.unsynced: self._handler_state_unsynced,
            ESyncState.syncing: self._handler_state_syncing,
            ESyncState.synced: self._handler_state_synced,
            ESyncState.forked: self._handler_state_forked,
        }

        _mapping[self.sync_state.state]()

    def stop_monitor_bk(self):
        try:
            reactor.monitor_bk.cancel()
        except Exception:  # No need to log this exception
            pass

    def restart_monitor_bk(self, delay: int):
        self.stop_monitor_bk()
        reactor.monitor_bk = reactor.callLater(delay, self.monitor_bk)

    def monitor_bk(self):
        # FIXME: Too many magic numbers / timing constants
        # FIXME: This is obsolete
        time_diff1 = ntp.getTime() - self.last_pow_cycle
        if 90 < time_diff1:
            if self.sync_state.state == ESyncState.unsynced:
                if ntp.getTime() - self.last_bk_time > 120:
                    self.last_pow_cycle = ntp.getTime()
                    logger.info(' POW cycle activated by monitor_bk() ')
                    self.update_node_state(ESyncState.synced)
                reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)
                return

        time_diff2 = ntp.getTime() - self.last_pb_time
        if self.sync_state.state == ESyncState.syncing and time_diff2 > 60:
            self.update_node_state(ESyncState.unsynced)
            self.epoch_diff = -1

        reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)

    def initialize_pow(self):
        reactor.callLater(0, self.update_node_state, ESyncState.synced)
        reactor.callLater(60, self.monitor_miner)

    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def restart_unsynced_logic(self, delay=0):
        logger.info('Restarting unsynced logic in %s seconds', delay)
        try:
            reactor.unsynced_logic.cancel()
        except Exception:  # No need to log this exception
            pass

        reactor.unsynced_logic = reactor.callLater(delay, self.unsynced_logic)

    def unsynced_logic(self):
        if self.sync_state.state != ESyncState.synced:
            self.p2p_factory.broadcast_get_synced_state()
            reactor.request_peer_blockheight = reactor.callLater(0, self.p2p_factory.request_peer_blockheight)
            reactor.unsynced_logic = reactor.callLater(20, self.start_download)

    def start_download(self):
        # FIXME: Why PoW is downloading blocks?
        # add peers and their identity to requested list
        # FMBH
        if self.sync_state.state == ESyncState.synced:
            return

        logger.info('Checking Download..')

        if self.p2p_factory.num_connections == 0:
            logger.warning('No connected peers. Moving to synced state')
            self.update_node_state(ESyncState.synced)
            return

        self.update_node_state(ESyncState.syncing)
        logger.info('Initializing download from %s', self.chain_manager.height + 1)
        self.p2p_factory.randomize_block_fetch()

    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################
    ##############################################

    def monitor_miner(self):
        reactor.callLater(15, self.monitor_miner)

        if not config.user.mining_enabled:
            return
        if not self.miner.isRunning() or self.miner_toggler:
            logger.debug('Mine next called by monitor_miner')
            self.miner_toggler = False
            self._mine_next(self.chain_manager.last_block)
        elif self.miner.solutionAvailable():
            self.miner_toggler = True
        else:
            self.miner_toggler = False

    def add_future_block(self, block):
        self.future_blocks[block.headerhash] = block
        if len(self.future_blocks) > config.dev.max_future_blocks_length:
            self.future_blocks.popitem(False)

    def process_future_blocks(self):
        keys = list(self.future_blocks.keys())
        for key in keys:
            block = self.future_blocks[key]
            if block.is_future_block():
                return
            self.pre_block_logic(block)
            del self.future_blocks[key]

    def pre_block_logic(self, block: Block):
        logger.debug('LOCK - TRY - pre_block_logic')
        with self.miner.lock:
            logger.debug('LOCK - LOCKED - pre_block_logic')

            if not block.validate(self.chain_manager, self.future_blocks):
                logger.warning('Block Validation failed for #%s %s', block.block_number, bin2hstr(block.headerhash))
                return

            if block.is_future_block():
                delay = abs(block.timestamp - ntp.getTime()) + 1
                reactor.callLater(delay, self.process_future_blocks)
                self.add_future_block(block)
                return

            logger.debug('Inside add_block')
            result = self.chain_manager.add_block(block)

            logger.debug('trigger_miner %s', self.chain_manager.trigger_miner)
            if self.chain_manager.trigger_miner:
                logger.debug('try last block')
                last_block = self.chain_manager.last_block
                logger.debug('got last block')
                self._mine_next(last_block)

            if not result:
                logger.debug('Block Rejected %s %s', block.block_number, bin2hstr(block.headerhash))
                return

            reactor.callLater(0, self.broadcast_block, block)
        logger.debug('LOCK - RELEASE - pre_block_logic')

    def broadcast_block(self, block):
        if self.sync_state.state == ESyncState.synced:
            self.p2p_factory.broadcast_block(block)

    def isSynced(self, block_timestamp) -> bool:
        if block_timestamp + config.dev.minimum_minting_delay > ntp.getTime():
            self.update_node_state(ESyncState.synced)
            return True
        return False

    def _mine_next(self, parent_block):
        if ntp.getTime() < self.suspend_mining_timestamp:
            return

        if config.user.mining_enabled:
            logger.debug('try get_block_metadata')
            parent_metadata = self.chain_manager.get_block_metadata(parent_block.headerhash)
            logger.debug('try prepare_next_unmined_block_template')
            self.miner.prepare_next_unmined_block_template(mining_address=self.mining_address,
                                                           tx_pool=self.chain_manager.tx_pool,
                                                           parent_block=parent_block,
                                                           parent_difficulty=parent_metadata.block_difficulty)
            logger.info('Mining Block #%s', parent_block.block_number + 1)
            self.miner.start_mining(parent_block, parent_metadata.block_difficulty)
