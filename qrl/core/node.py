# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import time
from collections import defaultdict
from functools import reduce
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr
from twisted.internet import reactor

from qrl.core import logger, config, BufferedChain, ntp
from qrl.core.Block import Block
from qrl.core.ESyncState import ESyncState
from qrl.core.Transaction import StakeTransaction, DestakeTransaction, Vote
from qrl.core.formulas import calc_seed
from qrl.core.formulas import score
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2


class SyncState:
    def __init__(self):
        self.state = ESyncState.unsynced
        self.epoch_diff = -1


class POS:
    def __init__(self,
                 buffered_chain: BufferedChain,
                 p2p_factory,
                 sync_state: SyncState,
                 time_provider):

        self.buffered_chain = buffered_chain
        self.p2p_factory = p2p_factory    # FIXME: Decouple from p2pFactory. Comms vs node logic
        self.p2p_factory.pos = self      # FIXME: Temporary hack to keep things working while refactoring

        self.sync_state = sync_state
        self.time_provider = time_provider
        self.stake = config.user.enable_auto_staking

        ########
        self.r1_time_diff = defaultdict(list)
        self.r2_time_diff = defaultdict(list)
        self.pos_blocknum = 0
        self.pos_callLater = None

        self.incoming_blocks = {}
        self.last_pos_cycle = 0
        self.last_selected_height = 0
        self.last_bk_time = 0
        self.last_pb_time = 0
        self.next_header_hash = None
        self.next_block_number = None

        self.blockheight_map = []
        self.retry_consensus = 0  # Keeps track of number of times consensus failed for the last blocknumber

        self.epoch_diff = None

    @property
    def master_mr(self):
        return self.p2p_factory.master_mr

    def _handler_state_unsynced(self):
        self.last_bk_time = time.time()
        self.restart_unsynced_logic()

    def _handler_state_syncing(self):
        self.last_pb_time = time.time()

    def _handler_state_synced(self):
        self.sync_state.epoch_diff = 0
        self.last_pos_cycle = time.time()
        self.restart_post_block_logic()

    def _handler_state_forked(self):
        self.stop_post_block_logic()

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
        # FIXME: Too complex.. too many nested ifs
        time_diff = time.time() - self.last_pos_cycle
        if (self.sync_state.state == ESyncState.synced or self.sync_state.state == ESyncState.unsynced) and \
                90 < time_diff:

            if self.sync_state.state == ESyncState.synced:
                self.stop_post_block_logic()
                self.update_node_state(ESyncState.unsynced)
                self.epoch_diff = -1
            elif time.time() - self.last_bk_time > 120:
                self.last_pos_cycle = time.time()
                logger.info(' POS cycle activated by monitor_bk() ')
                self.update_node_state(ESyncState.synced)

        if self.sync_state.state == ESyncState.syncing and time.time() - self.last_pb_time > 60:
            self.stop_post_block_logic()
            self.update_node_state(ESyncState.unsynced)
            self.epoch_diff = -1

        reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)

    # first block 1 is created with the stake list for epoch 0 decided from circulated st transactions

    def pre_pos_1(self, data=None):  # triggered after genesis for block 1..
        logger.info('pre_pos_1')
        # are we a staker in the stake list?
        genesis_block = self.buffered_chain.get_block(0)
        found = False
        for genesisBalance in genesis_block.genesis_balance:
            if genesisBalance.address.encode() == self.buffered_chain.staking_address:
                logger.info('Found in Genesis Address %s %s', genesisBalance.address.encode(), genesisBalance.balance)
                found = True
                break

        if not found:
            return

        logger.info('mining address: %s in the genesis.stake_list', self.buffered_chain.staking_address)
        xmss = self.buffered_chain.wallet.address_bundle[0].xmss
        tmphc = hashchain(xmss.get_seed_private(), epoch=0)
        self.buffered_chain.hash_chain[0] = tmphc.hashchain

        slave_xmss = self.buffered_chain.get_slave_xmss(0)
        if not slave_xmss:
            logger.info('Waiting for SLAVE XMSS to be done')
            reactor.callLater(5, self.pre_pos_1)
            return

        signing_xmss = self.buffered_chain.wallet.address_bundle[0].xmss
        st = StakeTransaction.create(activation_blocknumber=1,
                                     xmss=signing_xmss,
                                     slavePK=slave_xmss.pk(),
                                     hashchain_terminator=tmphc.hc_terminator)
        st.sign(signing_xmss)

        self.buffered_chain.tx_pool.add_tx_to_pool(st)

        # send the stake tx to generate hashchain terminators for the staker addresses..
        self.p2p_factory.broadcast_st(st)

        vote = Vote.create(addr_from=self.buffered_chain.wallet.address_bundle[0].address,
                           blocknumber=0,
                           headerhash=genesis_block.headerhash,
                           xmss=slave_xmss)

        vote.sign(slave_xmss)

        self.buffered_chain.add_vote(vote)

        # send the stake votes for genesis block
        self.p2p_factory.broadcast_vote(vote)

        logger.info('await delayed call to build staker list from genesis')
        reactor.callLater(5, self.pre_pos_2, st)

    def pre_pos_2(self, data=None):
        logger.info('pre_pos_2')
        if self.buffered_chain.height >= 1:
            return
        # assign hash terminators to addresses and generate a temporary stake list ordered by st.hash..

        tmp_list = []
        seed_list = []
        genesis_block = self.buffered_chain.get_block(0)
        total_genesis_stake_amount = 0
        for tx in self.buffered_chain.tx_pool.transaction_pool:
            tx.pbdata.nonce = 1
            if tx.subtype == qrl_pb2.Transaction.STAKE:
                for genesisBalance in genesis_block.genesis_balance:
                    if tx.txfrom == genesisBalance.address.encode() and tx.activation_blocknumber == 1:
                        tmp_list.append([tx.txfrom, tx.hash, 0, genesisBalance.balance, tx.slave_public_key])
                        seed_list.append(tx.hash)
                        # FIXME: This goes to stake validator list without verification, Security Risk
                        self.buffered_chain._chain.pstate.stake_validators_tracker.add_sv(genesisBalance.balance, tx, 1)
                        total_genesis_stake_amount += genesisBalance.balance

        self.buffered_chain.epoch_seed = calc_seed(seed_list)

        #  TODO : Needed to be reviewed later
        self.buffered_chain.stake_list = sorted(tmp_list,
                                                key=lambda staker: score(stake_address=staker[0],
                                                                         reveal_one=bin2hstr(sha256(str(
                                                                             reduce(lambda set1, set2: set1 + set2,
                                                                                    tuple(staker[1]))).encode())),
                                                                         balance=staker[3],
                                                                         seed=self.buffered_chain.epoch_seed))

        # self.buffered_chain.epoch_seed = format(self.buffered_chain.epoch_seed, 'x')  # FIXME: Why hex string?

        logger.info('genesis stakers ready = %s / %s', len(self.buffered_chain.stake_list),
                    config.dev.minimum_required_stakers)
        logger.info('node address: %s', self.buffered_chain.staking_address)

        # stake pool still not full..reloop..
        if len(self.buffered_chain.stake_list) < config.dev.minimum_required_stakers:
            self.p2p_factory.broadcast_st(data)
            logger.info('waiting for stakers.. retry in 5s')
            reactor.callID = reactor.callLater(5, self.pre_pos_2, data)
            return

        voteMetadata = self.buffered_chain.get_consensus(0)
        consensus_ratio = voteMetadata.total_stake_amount / total_genesis_stake_amount

        if consensus_ratio < 0.51:
            logger.info('Consensus lower than 51%%.. retry in 5s')
            reactor.callID = reactor.callLater(5, self.pre_pos_2, data)
            return

        if self.buffered_chain.staking_address == self.buffered_chain.stake_list[0][0]:
            logger.info('designated to create block 1: building block..')

            tmphc = hashchain(self.buffered_chain.wallet.address_bundle[0].xmss.get_seed_private())

            # create the genesis block 2 here..
            reveal_hash = self.buffered_chain.select_hashchain(self.buffered_chain.staking_address,
                                                               tmphc.hashchain,
                                                               blocknumber=1)

            b = self.buffered_chain.create_block(reveal_hash[-2])  # FIXME: This is incorrect, rewire
            self.pre_block_logic(b)  # FIXME: Ignore return value?
        else:
            logger.info('await block creation by stake validator: %s', self.buffered_chain.stake_list[0][0])
            self.last_bk_time = time.time()
            self.restart_unsynced_logic()

    def process_transactions(self, num):
        tmp_num = num
        for tx in self.buffered_chain.tx_pool.pending_tx_pool:
            tmp_num -= 1
            tx_peer = tx[1]
            tx = tx[0]
            if not tx.validate():
                logger.info('>>>TX %s failed validate_tx', tx.txhash)
                continue

            tx_state = self.buffered_chain.get_stxn_state(blocknumber=self.buffered_chain.height, addr=tx.txfrom)

            is_valid_state = tx.validate_extended(tx_state=tx_state,
                                                  transaction_pool=self.buffered_chain.tx_pool.transaction_pool)

            if not is_valid_state:
                logger.info('>>>TX %s failed state_validate', tx.txhash)
                continue

            logger.info('>>>TX - %s from - %s relaying..', tx.txhash, tx_peer.transport.getPeer().host)
            self.buffered_chain.tx_pool.add_tx_to_pool(tx)

            txn_msg = tx_peer.wrap_message('TX', tx.to_json())
            for peer in tx_peer.factory.peer_connections:
                if peer != tx_peer:
                    # FIXME: Breaks encapsulation
                    peer.transport.write(txn_msg)

        for i in range(num - tmp_num):
            del self.buffered_chain.tx_pool.pending_tx_pool[0]
            del self.buffered_chain.tx_pool.pending_tx_pool_hash[0]

    def create_new_block(self, reveal_hash, last_block_number) -> Optional[Block]:
        logger.info('create_new_block #%s', (last_block_number + 1))
        block_obj = self.buffered_chain.create_stake_block(reveal_hash, last_block_number)
        return block_obj

    def restart_unsynced_logic(self, delay=0):
        logger.info('Restarting unsynced logic in %s seconds', delay)
        try:
            reactor.unsynced_logic.cancel()
        except Exception:  # No need to log this exception
            pass

        reactor.unsynced_logic = reactor.callLater(delay, self.unsynced_logic)

    def unsynced_logic(self):
        '''
        Unsynced Logic
        1.	Request for maximum blockheight and passes bock number X
        2.	Peers response chain height with headerhash and the headerhash of block number X
        3.	Unsynced node, selects most common chain height, matches the headerhash of block number X
        4.	If headerhash of block number X doesn't match, change state to Forked
        5.	If headerhash of block number X matches, perform Downloading of blocks from those selected peers
        '''
        if self.sync_state.state != ESyncState.synced:
            self.p2p_factory.broadcast_get_synced_state()

            reactor.unsynced_logic = reactor.callLater(20, self.start_download)

    def start_download(self):
        # add peers and their identity to requested list
        # FMBH
        if self.sync_state.state == ESyncState.synced:
            return

        logger.info('Checking Download..')

        # FIXME: unsafe access to synced_peers
        if not self.p2p_factory.synced_peers:
            logger.warning('No connected peers in synced state. Retrying...')
            self.update_node_state(ESyncState.unsynced)
            return

        self.update_node_state(ESyncState.syncing)
        logger.info('Initializing download from %s', self.buffered_chain.height + 1)
        self.randomize_block_fetch()

    def pre_block_logic(self, block: Block) -> bool:
        # FIXME: Ensure that the chain is in memory

        chain_buffer_height = self.buffered_chain.height
        last_block_before = self.buffered_chain.get_last_block()

        if block.block_number < self.buffered_chain.height:
            return False

        # FIXME: Simplify logic
        if self.sync_state.state == ESyncState.synced:
            if not self.buffered_chain.add_block(block):
                return False
        elif chain_buffer_height + 1 == block.block_number:
            if block.block_number > 1:
                if not self.buffered_chain.add_block(block):
                    return False
            elif block.block_number == 1:
                if not self.buffered_chain.add_block(block):
                    return False
            self.isSynced(block.timestamp)
        else:
            self.buffered_chain.add_pending_block(block)

        if self.sync_state.state == ESyncState.synced:
            last_block_after = self.buffered_chain.get_last_block()
            self.last_pos_cycle = time.time()
            self.p2p_factory.broadcast_block(block)
            if last_block_before.headerhash != last_block_after.headerhash:
                self.schedule_pos(block.block_number + 1)

        return True

    def schedule_pos(self, blocknumber):
        if self.sync_state.state == ESyncState.synced:
            if self.pos_callLater and self.pos_callLater.active():
                if blocknumber - self.pos_blocknum == 1:
                    return

            self.restart_post_block_logic(blocknumber)

    def stop_post_block_logic(self):
        try:
            self.pos_callLater.cancel()
        except Exception:  # No need to log this exception
            pass

        try:
            self.vote_callLater.cancel()
        except Exception:
            pass

    def restart_post_block_logic(self, blocknumber=-1, delay=None):
        if blocknumber == -1:
            blocknumber = self.buffered_chain.height + 1

        if not delay:
            last_block = self.buffered_chain.get_block(blocknumber - 1)
            last_block_timestamp = last_block.timestamp
            curr_timestamp = int(ntp.getTime())

            delay = max(5, last_block_timestamp + config.dev.minimum_minting_delay - curr_timestamp)

        self.stop_post_block_logic()
        self.pos_callLater = reactor.callLater(delay,
                                               self.post_block_logic,
                                               blocknumber=blocknumber)
        should_vote = False
        if blocknumber > 1:
            stake_list = self.buffered_chain.stake_list_get(blocknumber - 1)
            if self.buffered_chain.staking_address in stake_list:
                stake_validator = stake_list[self.buffered_chain.staking_address]
                if stake_validator.is_active and not stake_validator.is_banned:
                    should_vote = True
        else:
            genesis_block = self.buffered_chain.get_block(0)
            for genesisBalance in genesis_block.genesis_balance:
                if genesisBalance.address.encode() == self.buffered_chain.staking_address:
                    should_vote = True
                    break

        if should_vote:
            vote_delay = max(0, delay - config.dev.vote_x_seconds_before_next_block)

            self.vote_callLater = reactor.callLater(vote_delay,
                                                    self.create_vote_tx,
                                                    blocknumber=blocknumber - 1)

        self.pos_blocknum = blocknumber

    def create_next_block(self, blocknumber, activation_blocknumber) -> bool:
        if self.buffered_chain.get_slave_xmss(blocknumber):
            hash_chain = self.buffered_chain.hash_chain_get(blocknumber)

            my_reveal = hash_chain[::-1][blocknumber - activation_blocknumber + 1]
            block = self.create_new_block(my_reveal, blocknumber - 1)

            return self.pre_block_logic(block)  # broadcast this block

        return False

    def check_consensus(self, blocknumber) -> bool:
        voteMetadata = self.buffered_chain.get_consensus(blocknumber - 1)
        consensus_headerhash = self.buffered_chain.get_consensus_headerhash(blocknumber - 1)

        if not consensus_headerhash:
            logger.warning('Consensus is still None, rescheduling post_block_logic after 5 sec')
            self.restart_post_block_logic(blocknumber, 5)
            return False

        prev_sv_tracker = self.buffered_chain.get_stake_validators_tracker(blocknumber)

        consensus_ratio = voteMetadata.total_stake_amount / prev_sv_tracker.get_total_stake_amount()

        if consensus_ratio < 0.51:
            logger.warning('Consensus below 51%%, rescheduling post_block_logic after 5 sec')
            self.retry_consensus += 1
            if self.retry_consensus >= config.dev.max_consensus_retry and self.buffered_chain.height > 1:
                self.retry_consensus = 0
                self.buffered_chain.remove_last_buffer_block()
                self.stop_post_block_logic()
                self.update_node_state(ESyncState.unsynced)
                return False
            self.restart_post_block_logic(blocknumber, 5)
            return False

        self.retry_consensus = 0
        prev_block = self.buffered_chain.get_block(blocknumber - 1)

        if consensus_headerhash != prev_block.headerhash:
            logger.warning('Fork detected...')
            logger.warning('Fork from Block #%s', blocknumber - 1)
            logger.warning('Fork Recovery Started...')
            self.buffered_chain.expected_headerhash[blocknumber - 1] = consensus_headerhash
            self.buffered_chain.remove_last_buffer_block()
            self.stop_post_block_logic()
            self.update_node_state(ESyncState.unsynced)
            return False

        return True

    def post_block_logic(self, blocknumber):
        """
        post block logic we initiate the next POS cycle
        send ST, reset POS flags and remove unnecessary
        messages in chain.stake_reveal_one and _two..

        :return:
        """

        if not self.check_consensus(blocknumber):
            return

        if self.stake:
            future_stake_addresses = self.buffered_chain.future_stake_addresses(blocknumber)

            if self.buffered_chain.staking_address not in future_stake_addresses:
                self._create_stake_tx(blocknumber)

            stake_list = self.buffered_chain.stake_list_get(blocknumber)

            delay = config.dev.minimum_minting_delay
            if self.buffered_chain.staking_address in stake_list and stake_list[
                    self.buffered_chain.staking_address].is_active:
                if stake_list[self.buffered_chain.staking_address].is_banned:
                    logger.warning('You have been banned.')
                else:
                    activation_blocknumber = stake_list[self.buffered_chain.staking_address].activation_blocknumber
                    self.create_next_block(blocknumber, activation_blocknumber)
                    delay = None

            last_blocknum = self.buffered_chain.height
            self.restart_post_block_logic(last_blocknum + 1, delay)

        return

    def get_last_blockheight_endswith(self, current_blocknumber, ending_number):
        result = ((current_blocknumber // 100) * 100 + ending_number)

        if result > current_blocknumber:
            result -= 100

        return result

    def create_vote_tx(self, blocknumber: int):
        block = self.buffered_chain.get_block(blocknumber)
        if not block:
            logger.warning('Block #%s not found, cancelled voting', blocknumber)
            return
        signing_xmss = self.buffered_chain.get_slave_xmss(blocknumber)
        if not signing_xmss:
            logger.warning('Skipped Voting: Slave XMSS none, XMSS POOL might still be generating slave_xmss')
            return

        vote = Vote.create(addr_from=self.buffered_chain.wallet.address_bundle[0].address,
                           blocknumber=blocknumber,
                           headerhash=block.blockheader.headerhash,
                           xmss=signing_xmss)

        vote.sign(signing_xmss)

        # FIXME: Temporary fix, need to add ST txn into Genesis
        if blocknumber > 1:
            tx_state = self.buffered_chain.get_stxn_state(blocknumber + 1, vote.addr_from)

            stake_validators_tracker = self.buffered_chain.get_stake_validators_tracker(blocknumber)

            if not (vote.validate() and vote.validate_extended(tx_state, stake_validators_tracker.sv_dict)):
                logger.warning('Create Vote Txn failed due to validation failure')
                return

        self.buffered_chain.set_voted(blocknumber)

        self.buffered_chain.add_vote(vote)

        self.p2p_factory.broadcast_vote(vote)

    def _create_stake_tx(self, curr_blocknumber):
        sv_dict = self.buffered_chain.stake_list_get(curr_blocknumber)
        if self.buffered_chain.staking_address in sv_dict:
            activation_blocknumber = sv_dict[
                self.buffered_chain.staking_address].activation_blocknumber + config.dev.blocks_per_epoch
        else:
            activation_blocknumber = curr_blocknumber + 2  # Activate as Stake Validator, 2 blocks after current block

        balance = self.buffered_chain.get_stxn_state(curr_blocknumber, self.buffered_chain.staking_address).balance
        if balance < config.dev.minimum_staking_balance_required:
            logger.warning('Staking not allowed due to insufficient balance')
            logger.warning('Balance %s', balance)
            return

        slave_xmss = self.buffered_chain.get_slave_xmss(activation_blocknumber)
        if not slave_xmss:
            return

        signing_xmss = self.buffered_chain.wallet.address_bundle[0].xmss

        blocknumber_headerhash = dict()
        current_blocknumber = self.buffered_chain.height

        for stamp in config.dev.stamping_series:
            if stamp > current_blocknumber:
                continue
            blocknumber = self.get_last_blockheight_endswith(current_blocknumber, stamp)
            finalized_block = self.buffered_chain.get_block(blocknumber)
            if not finalized_block:
                logger.warning('Cannot make ST txn, unable to get blocknumber %s', blocknumber)
                return

            blocknumber_headerhash[blocknumber] = finalized_block.headerhash

        st = StakeTransaction.create(
            activation_blocknumber=activation_blocknumber,
            xmss=signing_xmss,
            slavePK=slave_xmss.pk()
        )

        st.sign(signing_xmss)
        tx_state = self.buffered_chain.get_stxn_state(curr_blocknumber, st.txfrom)
        if not (st.validate() and st.validate_extended(tx_state)):
            logger.warning('Create St Txn failed due to validation failure, will retry next block')
            return

        self.p2p_factory.broadcast_st(st)
        for num in range(len(self.buffered_chain.tx_pool.transaction_pool)):
            t = self.buffered_chain.tx_pool.transaction_pool[num]
            if t.subtype == qrl_pb2.Transaction.STAKE and st.hash == t.hash:
                if st.get_message_hash() == t.get_message_hash():
                    return
                self.buffered_chain.tx_pool.remove_tx_from_pool(t)
                break

        self.buffered_chain.tx_pool.add_tx_to_pool(st)
        self.buffered_chain.wallet.save_wallet()

    def make_destake_tx(self):
        curr_blocknumber = self.buffered_chain.height + 1
        stake_validators_tracker = self.buffered_chain.get_stake_validators_tracker(curr_blocknumber)

        # No destake txn required if mining address is not in stake_validator_list
        if self.buffered_chain.staking_address not in stake_validators_tracker.sv_dict and \
                self.buffered_chain.height not in stake_validators_tracker.future_stake_addresses:
            logger.warning('%s Not found in Stake Validator list, destake txn note required',
                           self.buffered_chain.staking_address)
            return

        # Skip if mining address is not active in either stake validator list
        if not ((self.buffered_chain.staking_address in stake_validators_tracker.sv_dict and
                 stake_validators_tracker.sv_dict[self.buffered_chain.staking_address].is_active) or
                (self.buffered_chain.staking_address in stake_validators_tracker.future_stake_addresses and
                    stake_validators_tracker.future_stake_addresses[self.buffered_chain.staking_address].is_active)):
            logger.warning('%s is already inactive in Stake validator list, destake txn not required',
                           self.buffered_chain.staking_address)
            return

        signing_xmss = self.buffered_chain.wallet.address_bundle[0].xmss

        de_stake_txn = DestakeTransaction.create(xmss=signing_xmss)

        de_stake_txn.sign(signing_xmss)
        tx_state = self.buffered_chain.get_stxn_state(curr_blocknumber, de_stake_txn.txfrom)
        if not (de_stake_txn.validate() and de_stake_txn.validate_extended(tx_state)):
            logger.warning('Make DeStake Txn failed due to validation failure')
            return

        self.p2p_factory.broadcast_destake(de_stake_txn)
        for num in range(len(self.buffered_chain.tx_pool.transaction_pool)):
            t = self.buffered_chain.tx_pool.transaction_pool[num]
            if t.subtype == qrl_pb2.Transaction.STAKE:
                if de_stake_txn.get_message_hash() == t.get_message_hash():
                    return
                self.buffered_chain.tx_pool.remove_tx_from_pool(t)
                break

        self.buffered_chain.tx_pool.add_tx_to_pool(de_stake_txn)
        self.buffered_chain.wallet.save_wallet()

        return True

    def isSynced(self, block_timestamp) -> bool:
        if block_timestamp + config.dev.minimum_minting_delay > ntp.getTime():
            self.update_node_state(ESyncState.synced)
            return True
        return False

    def randomize_block_fetch(self):
        if self.sync_state.state != ESyncState.syncing:
            return

        if self.sync_state.state == ESyncState.syncing:
            block = self.buffered_chain.get_last_block()
            block_timestamp = block.timestamp
            if self.isSynced(block_timestamp):
                return

        # FIXME: unsafe access to synced_peers
        if len(self.p2p_factory.synced_peers) == 0:
            logger.warning('No connected peers in synced state. Retrying...')
            self.update_node_state(ESyncState.unsynced)
            return

        reactor.download_monitor = reactor.callLater(20, self.randomize_block_fetch)

        # FIXME: unsafe access to synced_peers
        random_peer = random.sample(self.p2p_factory.synced_peers, 1)[0]
        blocknumber = self.buffered_chain.height + 1
        random_peer.fetch_block_n(blocknumber)
