# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
import time
from collections import defaultdict
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr
from twisted.internet import reactor

from qrl.core import config
from qrl.core.Miner import Miner
from qrl.core.Wallet import Wallet
from qrl.core.AddressState import AddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.misc import ntp, logger
from qrl.core.Block import Block
from qrl.core.ESyncState import ESyncState
from qrl.generated import qrl_pb2


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
                 time_provider):

        super().__init__(chain_manager)
        self.miner = Miner(self.create_next_block)
        self.chain_manager.set_miner(self.miner)

        self.mining_xmss = Wallet.get_new_address(config.dev.xmss_tree_height).xmss

        self.p2p_factory = p2p_factory  # FIXME: Decouple from p2pFactory. Comms vs node logic
        self.p2p_factory.pow = self  # FIXME: Temporary hack to keep things working while refactoring

        self.sync_state = sync_state
        self.time_provider = time_provider

        ########

        self.last_pow_cycle = 0
        self.last_bk_time = 0
        self.last_pb_time = 0

        self.epoch_diff = None

    ##################################################
    ##################################################
    ##################################################
    ##################################################

    def start(self):
        self.restart_monitor_bk(80)
        reactor.callLater(20, self.initialize_pow)

    def _handler_state_unsynced(self):
        self.miner.cancel()
        self.last_bk_time = time.time()
        self.restart_unsynced_logic()

    def _handler_state_syncing(self):
        self.miner.cancel()
        self.last_pb_time = time.time()

    def _handler_state_synced(self):
        self.last_pow_cycle = time.time()
        self.chain_manager.mine_next()

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
        time_diff1 = time.time() - self.last_pow_cycle
        if 90 < time_diff1:
            if self.sync_state.state == ESyncState.unsynced:
                if time.time() - self.last_bk_time > 120:
                    self.last_pow_cycle = time.time()
                    logger.info(' POW cycle activated by monitor_bk() ')
                    self.update_node_state(ESyncState.synced)
                reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)
                return

        time_diff2 = time.time() - self.last_pb_time
        if self.sync_state.state == ESyncState.syncing and time_diff2 > 60:
            self.update_node_state(ESyncState.unsynced)
            self.epoch_diff = -1

        reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)

    def initialize_pow(self):
        reactor.callLater(1, self._handler_state_unsynced)

    def create_new_block(self, last_block, mining_nonce) -> Optional[Block]:
        # FIXME: Embed into the previous code
        logger.info('create_new_block #%s', last_block.block_number + 1)
        block_obj = self.create_stake_block(last_block, mining_nonce)
        return block_obj

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

        if self.p2p_factory.connections == 0:
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

    def pre_block_logic(self, block: Block) -> bool:
        # FIXME: Ensure that the chain is in memory

        if not self.chain_manager.add_block(block):
            return False

        if self.sync_state.state == ESyncState.synced:
            self.p2p_factory.broadcast_block(block)

        return True

    def create_next_block(self, mining_nonce) -> bool:
        last_block = self.chain_manager.last_block
        block = self.create_new_block(last_block, mining_nonce)

        self.pre_block_logic(block)  # broadcast this block

    def isSynced(self, block_timestamp) -> bool:
        if block_timestamp + config.dev.minimum_minting_delay > ntp.getTime():
            self.update_node_state(ESyncState.synced)
            return True
        return False

    def create_stake_block(self, last_block: Block, mining_nonce) -> Optional[Block]:
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        # FIXME: Break encapsulation
        t_pool2 = copy.deepcopy(self.chain_manager.tx_pool.transaction_pool)
        del self.chain_manager.tx_pool.transaction_pool[:]
        ######

        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        tx_nonce = defaultdict(int)
        total_txn = len(t_pool2)
        txnum = 0
        address_txn = self.chain_manager.get_state(last_block.headerhash)

        while txnum < total_txn:
            tx = t_pool2[txnum]
            if tx.ots_key_reuse(address_txn, tx.ots_key):
                del t_pool2[txnum]
                total_txn -= 1
                continue
            if tx.txfrom not in address_txn:
                address_txn[tx.txfrom] = AddressState.get_default(tx.txfrom)
            if tx.subtype == qrl_pb2.Transaction.TRANSFER:

                if address_txn[tx.txfrom].balance < tx.amount:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s', address_txn[tx.txfrom].balance,
                                   tx.amount)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.MESSAGE:
                if address_txn[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid message tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Free %s', address_txn[tx.txfrom].balance, tx.fee)
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.TOKEN:
                if tx.owner not in address_txn:
                    address_txn[tx.owner] = AddressState.get_default(tx.owner)
                for initial_balance in tx.initial_balances:
                    if initial_balance.address not in address_txn:
                        address_txn[initial_balance.address] = AddressState.get_default(initial_balance.address)
                if address_txn[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Fee %s',
                                   address_txn[tx.txfrom].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.TRANSFERTOKEN:
                if address_txn[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   address_txn[tx.txfrom].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if bin2hstr(tx.token_txhash).encode() not in address_txn[tx.txfrom].tokens:
                    logger.warning('%s doesnt own any token with token_txnhash %s', tx.txfrom,
                                   bin2hstr(tx.token_txhash).encode())
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if address_txn[tx.txfrom].tokens[bin2hstr(tx.token_txhash).encode()] < tx.amount:
                    logger.warning('Token Transfer amount exceeds available token')
                    logger.warning('Token Txhash %s', bin2hstr(tx.token_txhash).encode())
                    logger.warning('Available Token Amount %s',
                                   address_txn[tx.txfrom].tokens[bin2hstr(tx.token_txhash).encode()])
                    logger.warning('Transaction Amount %s', tx.amount)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.LATTICE:
                if address_txn[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   address_txn[tx.txfrom].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            tx.apply_on_state(address_txn)

            self.chain_manager.tx_pool.add_tx_to_pool(tx)
            tx_nonce[tx.txfrom] += 1
            tx._data.nonce = address_txn[tx.txfrom].nonce + tx_nonce[tx.txfrom]
            txnum += 1

        block = Block.create(mining_nonce=mining_nonce,
                             block_number=last_block.block_number + 1,
                             prevblock_headerhash=last_block.headerhash,
                             transactions=[],
                             signing_xmss=self.mining_xmss,
                             nonce=2)

        # reset the pool back
        # FIXME: Reset pool from here?
        self.chain_manager.tx_pool.transaction_pool = copy.deepcopy(t_pool2)

        return block
