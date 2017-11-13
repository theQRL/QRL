# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import time
from collections import Counter, defaultdict
from functools import reduce
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr
from twisted.internet import reactor

from qrl.core.Block import Block
from qrl.core.formulas import calc_seed
from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_DESTAKE
from qrl.core import logger, config, BufferedChain, ntp
from qrl.core.formulas import score
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.ESyncState import ESyncState
from qrl.core.Transaction import StakeTransaction, DestakeTransaction, Vote
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256


class SyncState:
    def __init__(self):
        self.state = ESyncState.unsynced
        self.epoch_diff = -1


class POS:
    def __init__(self,
                 buffered_chain: BufferedChain,
                 p2pFactory,
                 sync_state: SyncState,
                 time_provider):

        self.buffered_chain = buffered_chain
        self.p2pFactory = p2pFactory  # FIXME: Decouple from p2pFactory. Comms vs node logic
        self.sync_state = sync_state
        self.time_provider = time_provider

        ########
        self.master_mr = MessageReceipt()
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
        self.fmbh_allowed_peers = {}
        self.fmbh_blockhash_peers = {}

        self.blockheight_map = []

    def update_node_state(self, new_sync_state):
        self.sync_state.state = new_sync_state
        logger.info('Status changed to %s', self.sync_state.state)
        if self.sync_state.state == ESyncState.synced:
            self.sync_state.epoch_diff = 0
            self.last_pos_cycle = time.time()
            self.restart_post_block_logic()
        elif self.sync_state.state == ESyncState.unsynced:
            self.last_bk_time = time.time()
            self.restart_unsynced_logic()
        elif self.sync_state.state == ESyncState.forked:
            self.stop_post_block_logic()
        elif self.sync_state.state == ESyncState.syncing:
            self.last_pb_time = time.time()

    def stop_monitor_bk(self):
        try:
            reactor.monitor_bk.cancel()
        except Exception:  # No need to log this exception
            pass

    def restart_monitor_bk(self, delay=60):
        self.stop_monitor_bk()
        reactor.monitor_bk = reactor.callLater(delay, self.monitor_bk)

    def monitor_bk(self):
        time_diff = time.time() - self.last_pos_cycle
        if (
                self.sync_state.state == ESyncState.synced or self.sync_state.state == ESyncState.unsynced) and 90 < time_diff:
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

    def peers_blockheight(self):
        if self.sync_state.state == ESyncState.syncing:
            return

        block_height_counter = Counter()

        for peer in self.p2pFactory.peers:
            block_height_counter[peer.block_height] += 1

        blocknumber = block_height_counter.most_common(1)
        if not blocknumber:
            return  # TODO : Re-Schedule with delay

        blocknumber = blocknumber[0][0]

        if blocknumber > self.buffered_chain.height:
            # pending_blocks['target'] = blocknumber
            logger.info('Calling downloader from peers_blockheight due to no POS CYCLE %s', blocknumber)
            logger.info('Download block from %s to %s', self.buffered_chain.height + 1, blocknumber)
            self.last_pb_time = time.time()
            self.update_node_state(ESyncState.syncing)
            self.randomize_block_fetch(self.buffered_chain.height + 1)
        return

    # pos functions. an asynchronous loop.

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
        self.p2pFactory.send_st_to_peers(st)

        vote = Vote.create(addr_from=self.buffered_chain.wallet.address_bundle[0].address,
                           blocknumber=0,
                           headerhash=genesis_block.headerhash,
                           xmss=slave_xmss)

        vote.sign(slave_xmss)

        self.buffered_chain.add_vote(vote)

        # send the stake votes for genesis block
        self.p2pFactory.send_vote_to_peers(vote)

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
            if tx.subtype == TX_SUBTYPE_STAKE:
                for genesisBalance in genesis_block.genesis_balance:
                    if tx.txfrom == genesisBalance.address.encode():
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

        #self.buffered_chain.epoch_seed = format(self.buffered_chain.epoch_seed, 'x')  # FIXME: Why hex string?

        logger.info('genesis stakers ready = %s / %s', len(self.buffered_chain.stake_list),
                    config.dev.minimum_required_stakers)
        logger.info('node address: %s', self.buffered_chain.staking_address)

        # stake pool still not full..reloop..
        if len(self.buffered_chain.stake_list) < config.dev.minimum_required_stakers:
            self.p2pFactory.send_st_to_peers(data)
            logger.info('waiting for stakers.. retry in 5s')
            reactor.callID = reactor.callLater(5, self.pre_pos_2, data)
            return

        voteMetadata = self.buffered_chain.get_consensus(0)
        consensus_ratio = voteMetadata.total_stake_amount / total_genesis_stake_amount

        if consensus_ratio < 0.51:
            logger.info('Consensus lower than 51%.. retry in 5s')
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

    def filter_reveal_one_two(self, blocknumber=None):
        if not blocknumber:
            blocknumber = self.buffered_chain._chain.blockchain[-1].block_number

        self.buffered_chain.stake_reveal_one = [s for s in self.buffered_chain.stake_reveal_one if s[2] > blocknumber]

    # TODO: Incomplete fn, use to select the maximum blockheight by consensus
    def select_blockheight_by_consensus(self):
        block_height_counter = Counter()
        # for identity in self.fmbh_allowed_peers:
        #    block_height_counter[s[2]] += 1
        target_block_height = block_height_counter.most_common(1)

        if len(target_block_height) == 0:
            return None

        last_selected_height = target_block_height[0][0]
        return last_selected_height

    '''
    Unsynced Logic
    1.	Request for maximum blockheight and passes bock number X
    2.	Peers response chain height with headerhash and the headerhash of block number X
    3.	Unsynced node, selects most common chain height, matches the headerhash of block number X
    4.	If headerhash of block number X doesn't match, change state to Forked
    5.	If headerhash of block number X matches, perform Downloading of blocks from those selected peers
    '''

    def restart_unsynced_logic(self, delay=0):
        try:
            reactor.unsynced_logic.cancel()
        except Exception:  # No need to log this exception
            pass

        reactor.unsynced_logic = reactor.callLater(delay, self.unsynced_logic)

    def unsynced_logic(self):
        if self.sync_state.state == ESyncState.synced:
            return

        self.fmbh_blockhash_peers = {}
        self.fmbh_allowed_peers = {}
        for peer in self.p2pFactory.peer_connections:
            self.fmbh_allowed_peers[peer.conn_identity] = None
            peer.fetch_FMBH()
        reactor.unsynced_logic = reactor.callLater(20, self.start_download)

    def start_download(self):
        # add peers and their identity to requested list
        # FMBH
        if self.sync_state.state == ESyncState.synced:
            return
        logger.info('Checking Download..')
        '''
        global fmbh_blockhash_peers
        max_height = None
        selected_blockhash = None
        for blockheaderhash in fmbh_blockhash_peers:
            if fmbh_blockhash_peers[blockheaderhash]['blocknumber']>max_height:
                max_height = fmbh_blockhash_peers[blockheaderhash]['blocknumber']
                selected_blockhash = blockheaderhash
        for peer in fmbh_blockhash_peers[selected_blockhash]['peers']:
            f.target_peers = {}
            f.target_peers[peer.conn_identity] = peer
        
        if max_height == None or max_height<=chain.height():
            height().update(NState.synced)
            return
        
        height().update(NState.syncing)
        pending_blocks['start_block'] = chain.blockchain[-1].blocknumber
        pending_blocks['target'] = fmbh_blockhash_peers[selected_blockhash]['blocknumber']
        pending_blocks['headerhash'] = selected_blockhash
        randomize_block_fetch(chain.height() + 1)
        '''
        tmp_max = -1
        max_headerhash = None
        for headerhash in self.fmbh_blockhash_peers:
            if self.fmbh_blockhash_peers[headerhash]['blocknumber'] > self.buffered_chain.height:
                if len(self.fmbh_blockhash_peers[headerhash]['peers']) > tmp_max:
                    tmp_max = len(self.fmbh_blockhash_peers[headerhash]['peers'])
                    max_headerhash = headerhash

        # Adding all peers
        # TODO only trusted peer
        # for peer in self.p2pFactory.peers:
        if not max_headerhash:
            logger.info('No peers responded FMBH request')
            return
        for peer in self.fmbh_blockhash_peers[max_headerhash]['peers']:
            self.p2pFactory.target_peers[peer.conn_identity] = peer
        self.update_node_state(ESyncState.syncing)
        logger.info('Initializing download from %s', self.buffered_chain.height + 1)
        self.randomize_block_fetch(self.buffered_chain.height + 1)

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
                if not self.buffered_chain._add_block_mainchain(block):
                    return False
            self.update_node_state(ESyncState.synced)
        else:
            self.buffered_chain.add_pending_block(block)

        if self.sync_state.state == ESyncState.synced:
            last_block_after = self.buffered_chain.get_last_block()
            self.last_pos_cycle = time.time()
            self.p2pFactory.send_block_to_peers(block)
            if last_block_before.headerhash != last_block_after.headerhash:
                self.schedule_pos(block.block_number + 1)

        return True

    def schedule_pos(self, blocknumber):
        if self.sync_state.state == ESyncState.synced:
            if self.pos_callLater and self.pos_callLater.active():
                if blocknumber > self.pos_blocknum:
                    return

            self.restart_post_block_logic(blocknumber)

    def stop_post_block_logic(self):
        try:
            self.pos_callLater.cancel()
        except Exception:  # No need to log this exception
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

        self.vote_callLater = reactor.callLater(delay - config.dev.vote_x_seconds_before_next_block,
                                                self.create_vote_tx,
                                                blocknumber=blocknumber-1)

        self.pos_blocknum = blocknumber

    def create_next_block(self, blocknumber, activation_blocknumber) -> bool:
        if self.buffered_chain.get_slave_xmss(blocknumber):
            hash_chain = self.buffered_chain.hash_chain_get(blocknumber)

            my_reveal = hash_chain[::-1][blocknumber - activation_blocknumber + 1]
            block = self.create_new_block(my_reveal, blocknumber - 1)

            return self.pre_block_logic(block)  # broadcast this block

        return False

    def post_block_logic(self, blocknumber):
        """
        post block logic we initiate the next POS cycle
        send ST, reset POS flags and remove unnecessary
        messages in chain.stake_reveal_one and _two..

        :return:
        """
        if self.p2pFactory.stake:
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
        signing_xmss = self.buffered_chain.get_slave_xmss(blocknumber)

        vote = Vote.create(addr_from=self.buffered_chain.wallet.address_bundle[0].address,
                           blocknumber=blocknumber,
                           headerhash=block.blockheader.headerhash,
                           xmss=signing_xmss)

        vote.sign(signing_xmss)

        tx_state = self.buffered_chain.get_stxn_state(blocknumber + 1, vote.addr_from)
        stake_validators = self.buffered_chain.get_stake_validators_tracker(blocknumber)

        if not (vote.validate() and vote.validate_extended(tx_state, stake_validators.sv_dict)):
            logger.warning('Create Vote Txn failed due to validation failure')
            return

        self.buffered_chain.set_voted(blocknumber)
        
        self.buffered_chain.add_vote(vote)

        self.p2pFactory.send_vote_to_peers(vote)

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

        self.p2pFactory.send_st_to_peers(st)
        for num in range(len(self.buffered_chain.tx_pool.transaction_pool)):
            t = self.buffered_chain.tx_pool.transaction_pool[num]
            if t.subtype == TX_SUBTYPE_STAKE and st.hash == t.hash:
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
                 stake_validators_tracker.sv_dict[self.buffered_chain.staking_address].is_active)
                or (self.buffered_chain.staking_address in stake_validators_tracker.future_stake_addresses and
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

        self.p2pFactory.send_destake_txn_to_peers(de_stake_txn)
        for num in range(len(self.buffered_chain.tx_pool.transaction_pool)):
            t = self.buffered_chain.tx_pool.transaction_pool[num]
            if t.subtype == TX_SUBTYPE_DESTAKE:
                if de_stake_txn.get_message_hash() == t.get_message_hash():
                    return
                self.buffered_chain.tx_pool.remove_tx_from_pool(t)
                break

        self.buffered_chain.tx_pool.add_tx_to_pool(de_stake_txn)
        self.buffered_chain.wallet.save_wallet()

        return True

    def randomize_block_fetch(self, blocknumber):
        if self.sync_state.state != ESyncState.syncing or blocknumber <= self.buffered_chain.height:
            return

        if len(list(self.p2pFactory.target_peers.keys())) == 0:
            logger.info(' No target peers found.. stopping download')
            return

        reactor.download_monitor = reactor.callLater(20,
                                                     self.randomize_block_fetch, blocknumber)

        random_peer = self.p2pFactory.target_peers[random.choice(list(self.p2pFactory.target_peers.keys()))]
        random_peer.fetch_block_n(blocknumber)

    def blockheight_map(self):
        """
        blockheight map for connected nodes - when the blockheight seems up to date after a sync or error,
        we check all connected nodes to ensure all on same chain/height..
        note - may not return correctly during a block propagation..
        once working alter to identify fork better..

        :return:
        """
        # i = [block_number, headerhash, self.transport.getPeer().host]

        logger.info('blockheight_map:')
        logger.info(self.blockheight_map)

        # first strip out any laggards..
        self.blockheight_map = [q for q in self.blockheight_map if q[0] >= self.buffered_chain.height]

        result = True

        # next identify any node entries which are not exactly correct..

        for s in self.blockheight_map:
            if s[0] == self.buffered_chain.height:
                # FIXME: It should not access variable directly
                if s[1] == self.buffered_chain._chain.blockchain[-1].headerhash:
                    logger.info(('node: ', s[2], '@', s[0], 'w/:', s[1], 'OK'))
            elif s[0] > self.buffered_chain.height:
                logger.info(('warning..', s[2], 'at blockheight', s[0]))
                result = False

        # wipe it..
        del self.blockheight_map[:]
        return result
