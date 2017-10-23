# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import time
from collections import Counter, defaultdict
from functools import reduce

from pyqrllib.pyqrllib import bin2hstr, sha2_256
from twisted.internet import reactor

from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_DESTAKE
from qrl.core import logger, config, fork
from qrl.core.fork import fork_recovery
from qrl.core.messagereceipt import MessageReceipt
from qrl.core.nstate import NState
from qrl.core.Transaction import StakeTransaction, DestakeTransaction
from qrl.crypto.hashchain import hashchain
from qrl.crypto.misc import sha256


class NodeState:
    def __init__(self):
        self.state = NState.unsynced
        self.epoch_diff = -1


class POS:
    def __init__(self, chain, p2pFactory, nodeState, ntp):
        self.master_mr = MessageReceipt()
        self.nodeState = nodeState
        self.ntp = ntp
        self.chain = chain
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

        self.p2pFactory = p2pFactory

    def update_node_state(self, state):
        self.nodeState.state = state
        logger.info('Status changed to %s', self.nodeState.state)
        if self.nodeState.state == NState.synced:
            self.nodeState.epoch_diff = 0
            self.last_pos_cycle = time.time()
            self.restart_post_block_logic()
        elif self.nodeState.state == NState.unsynced:
            self.last_bk_time = time.time()
            self.restart_unsynced_logic()
        elif self.nodeState.state == NState.forked:
            self.stop_post_block_logic()
        elif self.nodeState.state == NState.syncing:
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
        if (self.nodeState.state == NState.synced or self.nodeState.state == NState.unsynced) and 90 < time_diff:
            if self.nodeState.state == NState.synced:
                self.stop_post_block_logic()
                self.update_node_state(NState.unsynced)
                self.epoch_diff = -1
            elif time.time() - self.last_bk_time > 120:
                self.last_pos_cycle = time.time()
                logger.info(' POS cycle activated by monitor_bk() ')
                self.update_node_state(NState.synced)

        if self.nodeState.state == NState.syncing and time.time() - self.last_pb_time > 60:
            self.stop_post_block_logic()
            self.update_node_state(NState.unsynced)
            self.epoch_diff = -1
        reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)

    def peers_blockheight_headerhash(self):
        for peer in self.p2pFactory.peers:
            peer.fetch_headerhash_n(self.chain.m_blockheight())

    def check_fork_status(self):
        current_height = self.chain.m_blockheight()
        block_hash_counter = Counter()
        for peer in self.p2pFactory.peers:
            if current_height in list(peer.blocknumber_headerhash.keys()):
                block_hash_counter[peer.blocknumber_headerhash[current_height]] += 1

        blockhash = block_hash_counter.most_common(1)
        if blockhash:
            blockhash = blockhash[0][0]
            actual_blockhash = self.chain.m_get_block(current_height).blockheader.headerhash
            if actual_blockhash != blockhash:
                logger.info('Blockhash didnt matched in peers_blockheight()')
                logger.info('Local blockhash - %s', actual_blockhash)
                logger.info('Consensus blockhash - %s', blockhash)
                fork_recovery(current_height, self.chain, self.randomize_headerhash_fetch)
                return True
        return

    def peers_blockheight(self):
        if self.nodeState.state == NState.syncing:
            return
        if self.check_fork_status():
            return

        block_height_counter = Counter()

        for peer in self.p2pFactory.peers:
            block_height_counter[peer.block_height] += 1

        blocknumber = block_height_counter.most_common(1)
        if not blocknumber:
            return  # TODO : Re-Schedule with delay

        blocknumber = blocknumber[0][0]

        if blocknumber > self.chain.height():  # chain.m_blockheight():  len(chain.m_blockchain)
            # pending_blocks['target'] = blocknumber
            logger.info('Calling downloader from peers_blockheight due to no POS CYCLE %s', blocknumber)
            logger.info('Download block from %s to %s', self.chain.height() + 1, blocknumber)
            self.last_pb_time = time.time()
            self.update_node_state(NState.syncing)
            self.randomize_block_fetch(self.chain.height() + 1)
        return

    def schedule_peers_blockheight(self, delay=100):
        try:
            reactor.peers_blockheight.cancel()
        except Exception:  # No need to log this exception
            pass

        reactor.peers_blockheight = reactor.callLater(delay, self.peers_blockheight)
        try:
            reactor.peers_blockheight_headerhash.cancel()  # No need to log this exception
        except Exception as e:
            pass

        reactor.peers_blockheight_headerhash = reactor.callLater(70, self.peers_blockheight_headerhash)

    # pos functions. an asynchronous loop.

    # first block 1 is created with the stake list for epoch 0 decided from circulated st transactions

    def pre_pos_1(self, data=None):  # triggered after genesis for block 1..
        logger.info('pre_pos_1')
        # are we a staker in the stake list?
        genesis_info = self.chain.state.load_genesis_info()
        if self.chain.mining_address not in genesis_info:
            logger.info('%s %s', self.chain.mining_address, genesis_info)
            return

        logger.info('mining address: %s in the genesis.stake_list', self.chain.mining_address)
        xmss = self.chain.wallet.address_bundle[0].xmss
        tmphc = hashchain(xmss.get_seed_private(), epoch=0)
        self.chain.hash_chain = tmphc.hashchain
        self.chain.block_chain_buffer.hash_chain[0] = tmphc.hashchain

        tmpbalance = self.chain.state.balance(self.chain.mining_address)
        slave_xmss = self.chain.block_chain_buffer.get_slave_xmss(0)
        if not slave_xmss:
            logger.info('Waiting for SLAVE XMSS to be done')
            reactor.callLater(5, self.pre_pos_1)
            return

        signing_xmss = self.chain.wallet.address_bundle[0].xmss
        st = StakeTransaction.create(activation_blocknumber=1,
                                     xmss=signing_xmss,
                                     slavePK=slave_xmss.pk(),
                                     finalized_blocknumber=0,
                                     finalized_headerhash=sha2_256(config.dev.genesis_prev_headerhash.encode()),
                                     hashchain_terminator=tmphc.hc_terminator,
                                     balance=tmpbalance)
        st.sign(signing_xmss)

        self.chain.add_tx_to_pool(st)
        # send the stake tx to generate hashchain terminators for the staker addresses..
        self.p2pFactory.send_st_to_peers(st)
        logger.info('await delayed call to build staker list from genesis')
        reactor.callLater(5, self.pre_pos_2, st)

    def pre_pos_2(self, data=None):
        logger.info('pre_pos_2')
        if self.chain.height() >= 1:
            return
        # assign hash terminators to addresses and generate a temporary stake list ordered by st.hash..

        tmp_list = []
        genesis_info = self.chain.state.load_genesis_info()
        for tx in self.chain.transaction_pool:
            if tx.subtype == TX_SUBTYPE_STAKE:
                if tx.txfrom in genesis_info:
                    tmp_list.append([tx.txfrom, tx.hash, 0, genesis_info[tx.txfrom], tx.slave_public_key])
                    #FIX ME: This goes to stake validator list without verifiction, Security Risk
                    self.chain.state.stake_validators_list.add_sv(tx, 1)

        self.chain.block_chain_buffer.epoch_seed = self.chain.state.calc_seed(tmp_list)
        #  TODO : Needed to be reviewed later
        self.chain.stake_list = sorted(tmp_list,
                                       key=lambda staker: self.chain.score(stake_address=staker[0],
                                                                           reveal_one=bin2hstr(sha256(str(
                                                                               reduce(lambda set1, set2: set1 + set2,
                                                                                      tuple(staker[1]))).encode())),
                                                                           balance=staker[3],
                                                                           seed=self.chain.block_chain_buffer.epoch_seed))

        self.chain.block_chain_buffer.epoch_seed = format(self.chain.block_chain_buffer.epoch_seed, 'x')

        logger.info('genesis stakers ready = %s / %s', len(self.chain.stake_list), config.dev.minimum_required_stakers)
        logger.info('node address: %s', self.chain.mining_address)

        if len(self.chain.stake_list) < config.dev.minimum_required_stakers:  # stake pool still not full..reloop..
            self.p2pFactory.send_st_to_peers(data)
            logger.info('waiting for stakers.. retry in 5s')
            reactor.callID = reactor.callLater(5, self.pre_pos_2, data)
            return

        if self.chain.mining_address == self.chain.stake_list[0][0]:
            logger.info('designated to create block 1: building block..')

            tmphc = hashchain(self.chain.wallet.address_bundle[0].xmss.get_seed_private())

            # create the genesis block 2 here..
            reveal_hash = self.chain.select_hashchain(self.chain.mining_address,
                                                      tmphc.hashchain,
                                                      blocknumber=1)
            b = self.chain.m_create_block(reveal_hash[-2])
            self.pre_block_logic(b)
        else:
            logger.info('await block creation by stake validator: %s', self.chain.stake_list[0][0])
            self.last_bk_time = time.time()
            self.restart_unsynced_logic()
        return

    def process_transactions(self, num):
        tmp_num = num
        for tx in self.chain.pending_tx_pool:
            tmp_num -= 1
            tx_peer = tx[1]
            tx = tx[0]
            if not tx.validate():
                logger.info('>>>TX %s failed validate_tx', tx.txhash)
                continue

            block_chain_buffer = self.chain.block_chain_buffer
            tx_state = block_chain_buffer.get_stxn_state(blocknumber=block_chain_buffer.height(),
                                                         addr=tx.txfrom)

            is_valid_state = tx.validate_extended(tx_state=tx_state,
                                                  transaction_pool=self.chain.transaction_pool)

            if not is_valid_state:
                logger.info('>>>TX %s failed state_validate', tx.txhash)
                continue

            logger.info('>>>TX - %s from - %s relaying..', tx.txhash, tx_peer.transport.getPeer().host)
            self.chain.add_tx_to_pool(tx)

            txn_msg = tx_peer.wrap_message('TX', tx.to_json())
            for peer in tx_peer.factory.peer_connections:
                if peer != tx_peer:
                    peer.transport.write(txn_msg)

        for i in range(num - tmp_num):
            del self.chain.pending_tx_pool[0]
            del self.chain.pending_tx_pool_hash[0]

    # create new block..

    def create_new_block(self, reveal_hash, last_block_number):
        logger.info('create_new_block #%s', (last_block_number + 1))
        block_obj = self.chain.create_stake_block(reveal_hash, last_block_number)

        return block_obj

    def filter_reveal_one_two(self, blocknumber=None):
        if not blocknumber:
            blocknumber = self.chain.m_blockchain[-1].blockheader.blocknumber

        self.chain.stake_reveal_one = [s for s in self.chain.stake_reveal_one if s[2] > blocknumber]

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
        if self.nodeState.state == NState.synced:
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
        if self.nodeState.state == NState.synced:
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
            chain.state.update(NState.synced)
            return
        
        chain.state.update(NState.syncing)
        pending_blocks['start_block'] = chain.m_blockchain[-1].blockheader.blocknumber
        pending_blocks['target'] = fmbh_blockhash_peers[selected_blockhash]['blocknumber']
        pending_blocks['headerhash'] = selected_blockhash
        randomize_block_fetch(chain.height() + 1)
        '''
        tmp_max = -1
        max_headerhash = None
        for headerhash in self.fmbh_blockhash_peers:
            if self.fmbh_blockhash_peers[headerhash]['blocknumber'] > self.chain.height():
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
        self.update_node_state(NState.syncing)
        logger.info('Initializing download from %s', self.chain.height()+1)
        self.randomize_block_fetch(self.chain.height() + 1)

    def pre_block_logic(self, block):
        if len(self.chain.m_blockchain) == 0:
            self.chain.m_read_chain()

        blocknumber = block.blockheader.blocknumber
        chain_buffer_height = self.chain.block_chain_buffer.height()
        last_block_before = self.chain.block_chain_buffer.get_last_block()

        if blocknumber <= self.chain.height():
            return False

        if self.nodeState.state == NState.synced:
            if not self.chain.block_chain_buffer.add_block(block):
                return
        elif chain_buffer_height + 1 == blocknumber:
            if blocknumber > 1:
                if not self.chain.block_chain_buffer.add_block(block):
                    return
            elif blocknumber == 1:
                if not self.chain.add_block_mainchain(block):
                    return
            self.update_node_state(NState.synced)
        else:
            self.chain.block_chain_buffer.add_pending_block(block)

        if self.nodeState.state == NState.synced:
            last_block_after = self.chain.block_chain_buffer.get_last_block()
            self.last_pos_cycle = time.time()
            self.p2pFactory.send_block_to_peers(block)
            if last_block_before.blockheader.headerhash != last_block_after.blockheader.headerhash:
                self.schedule_pos(blocknumber + 1)

        return True

    def schedule_pos(self, blocknumber):
        if self.nodeState.state == NState.synced:
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
            blocknumber = self.chain.block_chain_buffer.height() + 1

        if not delay:
            last_block = self.chain.block_chain_buffer.get_block_n(blocknumber - 1)
            last_block_timestamp = last_block.blockheader.timestamp
            curr_timestamp = int(self.ntp.getTime())

            delay = max(5, last_block_timestamp + config.dev.minimum_minting_delay - curr_timestamp)

        self.stop_post_block_logic()
        self.pos_callLater = reactor.callLater(delay,
                                               self.post_block_logic,
                                               blocknumber=blocknumber)
        self.pos_blocknum = blocknumber

    def create_next_block(self, blocknumber, activation_blocknumber):
        if not self.chain.block_chain_buffer.get_slave_xmss(blocknumber):
            return

        hash_chain = self.chain.block_chain_buffer.hash_chain_get(blocknumber)

        my_reveal = hash_chain[::-1][blocknumber - activation_blocknumber + 1]

        block = self.create_new_block(my_reveal,
                                      blocknumber - 1)

        self.pre_block_logic(block)  # broadcast this block

    def post_block_logic(self, blocknumber):
        """
        post block logic we initiate the next POS cycle
        send ST, reset POS flags and remove unnecessary
        messages in chain.stake_reveal_one and _two..

        :return:
        """

        if self.p2pFactory.stake:
            mining_address = self.chain.mining_address

            future_stake_addresses = self.chain.block_chain_buffer.future_stake_addresses(blocknumber)

            if mining_address not in future_stake_addresses:
                self.make_st_tx(blocknumber)

            stake_list = self.chain.block_chain_buffer.stake_list_get(blocknumber)

            delay = config.dev.minimum_minting_delay
            if  mining_address in stake_list and stake_list[mining_address].is_active:
                if stake_list[mining_address].is_banned:
                    logger.warning('You have been banned.')
                else:
                    activation_blocknumber = stake_list[mining_address].activation_blocknumber
                    self.create_next_block(blocknumber, activation_blocknumber)
                    delay = None

            last_blocknum = self.chain.block_chain_buffer.height()
            self.restart_post_block_logic(last_blocknum + 1, delay)

        return

    def make_st_tx(self, curr_blocknumber):
        sv_list = self.chain.block_chain_buffer.stake_list_get(curr_blocknumber)
        if self.chain.mining_address in sv_list:
            activation_blocknumber = sv_list[self.chain.mining_address].activation_blocknumber + config.dev.blocks_per_epoch
        else:
            activation_blocknumber = curr_blocknumber + 2  # Activate as Stake Validator, 2 blocks after current block

        balance = self.chain.block_chain_buffer.get_stxn_state(curr_blocknumber, self.chain.mining_address)[1]
        if balance < config.dev.minimum_staking_balance_required:
            logger.warning('Staking not allowed due to insufficient balance')
            logger.warning('Balance %s', balance)
            return

        slave_xmss = self.chain.block_chain_buffer.get_slave_xmss(activation_blocknumber)
        if not slave_xmss:
            return

        signing_xmss = self.chain.wallet.address_bundle[0].xmss

        finalized_blocknumber = ((curr_blocknumber - 1) // config.dev.blocks_per_epoch) * config.dev.blocks_per_epoch
        finalized_block = self.chain.block_chain_buffer.get_block_n(finalized_blocknumber)
        if not finalized_block:
            logger.warning('Cannot make ST txn, unable to get blocknumber %s', finalized_blocknumber)
            return

        finalized_headerhash = finalized_block.blockheader.headerhash

        st = StakeTransaction.create(
            activation_blocknumber=activation_blocknumber,
            xmss=signing_xmss,
            slavePK=slave_xmss.pk(),
            finalized_blocknumber=finalized_blocknumber,
            finalized_headerhash=finalized_headerhash,
            balance=balance
        )

        st.sign(signing_xmss)
        tx_state = self.chain.block_chain_buffer.get_stxn_state(curr_blocknumber, st.txfrom)
        if not (st.validate() and st.validate_extended(tx_state)):
            logger.info('Make St Txn failed due to validation failure, will retry next block')
            return

        self.p2pFactory.send_st_to_peers(st)
        for num in range(len(self.chain.transaction_pool)):
            t = self.chain.transaction_pool[num]
            if t.subtype == TX_SUBTYPE_STAKE and st.hash == t.hash:
                if st.get_message_hash() == t.get_message_hash():
                    return
                self.chain.remove_tx_from_pool(t)
                break

        self.chain.add_tx_to_pool(st)
        self.chain.wallet.save_wallet()

    def make_destake_tx(self):
        curr_blocknumber = self.chain.block_chain_buffer.height() + 1
        stake_validators_list = self.chain.block_chain_buffer.get_stake_validators_list(curr_blocknumber)

        mining_address = self.chain.mining_address

        # No destake txn required if mining address is not in stake_validator_list
        if mining_address not in stake_validators_list.sv_list and \
                        self.chain.mining_address not in stake_validators_list.future_stake_addresses:
            logger.warning('%s Not found in Stake Validator list, destake txn note required', mining_address)
            return

        # Skip if mining address is not active in either stake validator list
        if not ((mining_address in stake_validators_list.sv_list and stake_validators_list.sv_list[mining_address].is_active)
                or (mining_address in stake_validators_list.future_stake_addresses and stake_validators_list.future_stake_addresses[mining_address].is_active)):
            logger.warning('%s is already inactive in Stake validator list, destake txn not required', mining_address)
            return

        signing_xmss = self.chain.wallet.address_bundle[0].xmss

        de_stake_txn = DestakeTransaction.create(xmss=signing_xmss)

        de_stake_txn.sign(signing_xmss)
        tx_state = self.chain.block_chain_buffer.get_stxn_state(curr_blocknumber, de_stake_txn.txfrom)
        if not (de_stake_txn.validate() and de_stake_txn.validate_extended(tx_state)):
            logger.warning('Make DeStake Txn failed due to validation failure')
            return

        self.p2pFactory.send_destake_txn_to_peers(de_stake_txn)
        for num in range(len(self.chain.transaction_pool)):
            t = self.chain.transaction_pool[num]
            if t.subtype == TX_SUBTYPE_DESTAKE:
                if de_stake_txn.get_message_hash() == t.get_message_hash():
                    return
                self.chain.remove_tx_from_pool(t)
                break

        self.chain.add_tx_to_pool(de_stake_txn)
        self.chain.wallet.save_wallet()

        return True

    def randomize_block_fetch(self, blocknumber):
        if self.nodeState.state != NState.syncing or blocknumber <= self.chain.height():
            return

        if len(list(self.p2pFactory.target_peers.keys())) == 0:
            logger.info(' No target peers found.. stopping download')
            return

        reactor.download_monitor = reactor.callLater(20,
                                                     self.randomize_block_fetch, blocknumber)

        random_peer = self.p2pFactory.target_peers[random.choice(list(self.p2pFactory.target_peers.keys()))]
        random_peer.fetch_block_n(blocknumber)

    def randomize_headerhash_fetch(self, block_number):
        if self.nodeState.state != NState.forked:
            return
        if block_number not in fork.pending_blocks or fork.pending_blocks[block_number][1] <= 10:  # retry only 11 times
            headerhash_monitor = reactor.callLater(15, self.randomize_headerhash_fetch, block_number)
            if len(self.p2pFactory.peers) > 0:
                try:
                    if len(self.p2pFactory.fork_target_peers) == 0:
                        for peer in self.p2pFactory.peers:
                            self.p2pFactory.fork_target_peers[peer.conn_identity] = peer
                    if len(self.p2pFactory.fork_target_peers) > 0:
                        random_peer = self.p2pFactory.fork_target_peers[
                            random.choice(
                                list(self.p2pFactory.fork_target_peers.keys())
                            )
                        ]
                        count = 0
                        if block_number in fork.pending_blocks:
                            count = fork.pending_blocks[block_number][1] + 1
                        fork.pending_blocks[block_number] = [
                            random_peer.conn_identity, count, None, headerhash_monitor
                        ]
                        random_peer.fetch_headerhash_n(block_number)
                except Exception as e:
                    logger.warning('Exception at randomize_headerhash_fetch %s', e)
            else:
                logger.info('No peers connected.. Will try again... randomize_headerhash_fetch: %s', block_number)
        else:
            self.update_node_state(NState.unsynced)

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
        logger.info(self.chain.blockheight_map)

        # first strip out any laggards..
        self.chain.blockheight_map = [q for q in self.chain.blockheight_map if q[0] >= self.chain.m_blockheight()]

        result = True

        # next identify any node entries which are not exactly correct..

        for s in self.chain.blockheight_map:
            if s[0] == self.chain.m_blockheight():
                if s[1] == self.chain.m_blockchain[-1].blockheader.headerhash:
                    logger.info(('node: ', s[2], '@', s[0], 'w/:', s[1], 'OK'))
            elif s[0] > self.chain.m_blockheight():
                logger.info(('warning..', s[2], 'at blockheight', s[0]))
                result = False

        # wipe it..

        del self.chain.blockheight_map[:]

        return result
