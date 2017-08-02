# QRL testnet node..
# -features POS, quantum secure signature scheme..

__author__ = 'pete'
import time, struct, random
from operator import itemgetter
from collections import Counter, defaultdict
import json

import configuration as c
import fork

import helper
from twisted.internet.protocol import ServerFactory, Protocol
from twisted.internet import reactor
from transaction import StakeTransaction, SimpleTransaction
from merkle import GEN_range, sha256
from messagereceipt import MessageReceipt
from copy import deepcopy
from decimal import Decimal
class NodeState:
    def __init__(self):
        self.state = 'unsynced'
        self.epoch_diff = -1


class POS:
    def __init__(self, chain, p2pFactory, nodeState, ntp):
        self.master_mr = MessageReceipt()
        self.nodeState = nodeState
        self.ntp = ntp
        self.chain = chain
        self.r1_time_diff = defaultdict(list)
        self.r2_time_diff = defaultdict(list)

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
        printL(('Status changed to ', self.nodeState.state))
        if self.nodeState.state == 'synced':
            self.nodeState.epoch_diff = 0
            self.last_pos_cycle = time.time()
            self.restart_post_block_logic()
        elif self.nodeState.state == 'unsynced':
            self.last_bk_time = time.time()
            self.restart_unsynced_logic()
        elif self.nodeState.state == 'forked':
            self.stop_post_block_logic()
        elif self.nodeState.state == 'syncing':
            self.last_pb_time = time.time()

    def stop_monitor_bk(self):
        try:
            reactor.monitor_bk.cancel()
        except:
            pass

    def restart_monitor_bk(self, delay=60):
        self.stop_monitor_bk()
        reactor.monitor_bk = reactor.callLater(delay, self.monitor_bk)

    def monitor_bk(self):
        if (
                        self.nodeState.state == 'synced' or self.nodeState.state == 'unsynced') and time.time() - self.last_pos_cycle > 90:
            if self.nodeState.state == 'synced':
                self.stop_post_block_logic()
                self.reset_everything()
                self.update_node_state('unsynced')
                self.epoch_diff = -1
            elif time.time() - self.last_bk_time > 120:
                self.last_pos_cycle = time.time()
                printL((' POS cycle activated by monitor_bk() '))
                self.update_node_state('synced')

        if self.nodeState.state == 'syncing' and time.time() - self.last_pb_time > 60:
            self.stop_post_block_logic()
            self.reset_everything()
            self.update_node_state('unsynced')
            self.epoch_diff = -1
        reactor.monitor_bk = reactor.callLater(60, self.monitor_bk)

    def peers_blockheight_headerhash(self):
        for peer in self.p2pFactory.peers:
            peer.fetch_headerhash_n(self.chain.m_blockheight())

    def check_fork_status(self):
        current_height = self.chain.m_blockheight()
        block_hash_counter = Counter()
        for peer in self.p2pFactory.peers:
            if current_height in peer.blocknumber_headerhash.keys():
                block_hash_counter[peer.blocknumber_headerhash[current_height]] += 1

        blockhash = block_hash_counter.most_common(1)
        if blockhash:
            blockhash = blockhash[0][0]
            actual_blockhash = self.chain.m_get_block(current_height).blockheader.headerhash
            if actual_blockhash != blockhash:
                printL(('Blockhash didnt matched in peers_blockheight()'))
                printL(('Local blockhash - ', actual_blockhash))
                printL(('Consensus blockhash - ', blockhash))
                fork.fork_recovery(current_height, self.chain, self.randomize_headerhash_fetch)
                return True
        return

    def peers_blockheight(self):
        if self.nodeState.state == 'syncing':
            return
        if self.check_fork_status():
            return

        block_height_counter = Counter()

        for peer in self.p2pFactory.peers:
            block_height_counter[peer.blockheight] += 1

        blocknumber = block_height_counter.most_common(1)
        if not blocknumber:
            return  # TODO : Re-Schedule with delay

        blocknumber = blocknumber[0][0]

        if blocknumber > self.chain.height():  # chain.m_blockheight():  len(chain.m_blockchain)
            # pending_blocks['target'] = blocknumber
            printL(('Calling downloader from peers_blockheight due to no POS CYCLE ', blocknumber))
            printL(('Download block from ', self.chain.height() + 1, ' to ', blocknumber))
            self.last_pb_time = time.time()
            self.update_node_state('syncing')
            self.randomize_block_fetch(self.chain.height() + 1)
        return

    def schedule_peers_blockheight(self, delay=100):
        try:
            reactor.peers_blockheight.cancel()
        except Exception:
            pass
        reactor.peers_blockheight = reactor.callLater(delay, self.peers_blockheight)
        try:
            reactor.peers_blockheight_headerhash.cancel()
        except Exception:
            pass
        reactor.peers_blockheight_headerhash = reactor.callLater(70, self.peers_blockheight_headerhash)

    # pos functions. an asynchronous loop.

    # first block 1 is created with the stake list for epoch 0 decided from circulated st transactions

    def pre_pos_1(self, data=None):  # triggered after genesis for block 1..
        printL(('pre_pos_1'))
        # are we a staker in the stake list?

        if self.chain.mining_address in self.chain.m_blockchain[0].stake_list:
            printL(('mining address:', self.chain.mining_address, ' in the genesis.stake_list'))

            self.chain.my[0][1].hashchain(epoch=0)
            self.chain.hash_chain = self.chain.my[0][1].hc
            self.chain.block_chain_buffer.hash_chain[0] = self.chain.my[0][1].hc

            printL(('hashchain terminator: ', self.chain.my[0][1].hc_terminator))
            st = StakeTransaction().create_stake_transaction(mining_address=self.chain.mining_address,
                                                             blocknumber=0,
                                                             data=self.chain.my[0][1],
                                                             hashchain_terminator=self.chain.my[0][1].hc_terminator,
                                                             first_hash=self.chain.my[0][1].hc[-1][-2],
                                                             balance=self.chain.state.state_balance(self.chain.mining_address))
            self.chain.wallet.f_save_winfo()
            self.chain.add_st_to_pool(st)
            # send the stake tx to generate hashchain terminators for the staker addresses..
            self.p2pFactory.send_st_to_peers(st)
            printL(('await delayed call to build staker list from genesis'))
            reactor.callLater(5, self.pre_pos_2, st)
            return

        printL(('not in stake list..no further pre_pos_x calls'))
        return

    def pre_pos_2(self, data=None):
        printL(('pre_pos_2'))
        if self.chain.height() >= 1:
            return
        # assign hash terminators to addresses and generate a temporary stake list ordered by st.hash..

        tmp_list = []

        for st in self.chain.stake_pool:
            if st.txfrom in self.chain.m_blockchain[0].stake_list:
                tmp_list.append([st.txfrom, st.hash, 0, st.first_hash, self.chain.state.state_balance(st.txfrom)])

        # required as doing chain.stake_list.index(s) which will result into different number on different server
        self.chain.block_chain_buffer.epoch_seed = self.chain.state.calc_seed(tmp_list)
        self.chain.stake_list = sorted(tmp_list,
                                       key=lambda staker: self.chain.score(stake_address=staker[0],
                                                                           reveal_one=sha256(str(staker[1])),
                                                                           balance=self.chain.state.state_balance(st.txfrom),
                                                                           seed=self.chain.block_chain_buffer.epoch_seed))

        printL(('genesis stakers ready = ', len(self.chain.stake_list), '/', c.minimum_required_stakers))
        printL(('node address:', self.chain.mining_address))

        if len(self.chain.stake_list) < c.minimum_required_stakers:  # stake pool still not full..reloop..
            self.p2pFactory.send_st_to_peers(data)
            printL(('waiting for stakers.. retry in 5s'))
            reactor.callID = reactor.callLater(5, self.pre_pos_2, data)
            return
        printL (( str(self.chain.stake_list) ))

        if self.chain.mining_address == self.chain.stake_list[0][0]:
            printL(('designated to create block 1: building block..'))

            # create the genesis block 2 here..
            my_hash_chain, _ = self.chain.select_hashchain(self.chain.m_blockchain[-1].blockheader.headerhash,
                                                           self.chain.mining_address, self.chain.my[0][1].hc,
                                                           blocknumber=1)
            b = self.chain.m_create_block(my_hash_chain[-2])
            self.pre_block_logic(b)
        else:
            printL(('await block creation by stake validator:', self.chain.stake_list[0][0]))
            self.last_bk_time = time.time()
            self.restart_unsynced_logic()
        return

    def process_transactions(self, num):
        tmp_num = num
        for tx in self.chain.pending_tx_pool:
            tmp_num -= 1
            tx_peer = tx[1]
            tx = tx[0]
            if tx.validate_tx() != True:
                printL(('>>>TX ', tx.txhash, 'failed validate_tx'))
                continue

            isValidState = tx.state_validate_tx(
                state=self.chain.state,
                transaction_pool=self.chain.transaction_pool
            )
            if not isValidState:
                printL(('>>>TX', tx.txhash, 'failed state_validate'))
                continue

            printL(('>>>TX - ', tx.txhash, ' from - ', tx_peer.transport.getPeer().host, ' relaying..'))
            self.chain.add_tx_to_pool(tx)

            txn_msg = tx_peer.wrap_message('TX', tx.transaction_to_json())
            for peer in tx_peer.factory.peers:
                if peer != tx_peer:
                    peer.transport.write(txn_msg)

        for i in range(num - tmp_num):
            del self.chain.pending_tx_pool[0]
            del self.chain.pending_tx_pool_hash[0]

    # create new block..

    def create_new_block(self, winner, reveals, vote_hashes, last_block_number):
        printL(('create_new_block #', (last_block_number+1) ))
        tx_list = []
        for t in self.chain.transaction_pool:
            tx_list.append(t.txhash)
        block_obj = self.chain.create_stake_block(tx_list, winner, reveals, vote_hashes, last_block_number)

        return block_obj

    def reset_everything(self, data=None):
        printL(('** resetting loops and emptying chain.stake_reveal_one and chain.expected_winner '))
        for r in self.chain.stake_reveal_one:
            msg_hash = r[5]
            self.master_mr.deregister(msg_hash, 'R1')

        del self.chain.stake_reveal_one[:]
        return

    def filter_reveal_one_two(self, blocknumber=None):
        if not blocknumber:
            blocknumber = self.chain.m_blockchain[-1].blockheader.blocknumber

        self.chain.stake_reveal_one = filter(lambda s: s[2] > blocknumber,
                                             self.chain.stake_reveal_one)

        return

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
        except:
            pass
        reactor.unsynced_logic = reactor.callLater(delay, self.unsynced_logic)

    def unsynced_logic(self):
        if self.nodeState.state == 'synced':
            return

        self.fmbh_blockhash_peers = {}
        self.fmbh_allowed_peers = {}
        for peer in self.p2pFactory.peers:
            self.fmbh_allowed_peers[peer.identity] = None
            peer.fetch_FMBH()
        reactor.unsynced_logic = reactor.callLater(20, self.start_download)

    def start_download(self):
        # add peers and their identity to requested list
        # FMBH
        if self.nodeState.state == 'synced':
            return
        printL(('Checking Download..'))
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
            f.target_peers[peer.identity] = peer
        
        if max_height == None or max_height<=chain.height():
            chain.state.update('synced')
            return
        
        chain.state.update('syncing')
        pending_blocks['start_block'] = chain.m_blockchain[-1].blockheader.blocknumber
        pending_blocks['target'] = fmbh_blockhash_peers[selected_blockhash]['blocknumber']
        pending_blocks['headerhash'] = selected_blockhash
        randomize_block_fetch(chain.height() + 1)
        '''
        max = -1
        max_headerhash = None
        for headerhash in self.fmbh_blockhash_peers:
            if self.fmbh_blockhash_peers[headerhash]['blocknumber'] > self.chain.height():
                if len(self.fmbh_blockhash_peers[headerhash]['peers']) > max:
                    max = len(self.fmbh_blockhash_peers[headerhash]['peers'])
                    max_headerhash = headerhash

        # Adding all peers
        # TODO only trusted peer
        #for peer in self.p2pFactory.peers:
        if not max_headerhash:
            printL (( 'No peers responded FMBH request'))
            return
        for peer in self.fmbh_blockhash_peers[max_headerhash]['peers']:
            self.p2pFactory.target_peers[peer.identity] = peer
        self.update_node_state('syncing')
        self.randomize_block_fetch(self.chain.height() + 1)

    def pre_block_logic(self, block, peer_identity=None):
        if len(self.chain.m_blockchain) == 0:
            self.chain.m_read_chain()

        blocknumber = block.blockheader.blocknumber
        headerhash = block.blockheader.headerhash
        prev_blockheaderhash = block.blockheader.prev_blockheaderhash
        curr_epoch = self.chain.height() / c.blocks_per_epoch
        next_epoch = (self.chain.height() + 1) / c.blocks_per_epoch
        chain_buffer_height = self.chain.block_chain_buffer.height()

        if blocknumber <= self.chain.height():
            return False

        if self.nodeState.state == 'synced':
            if self.chain.block_chain_buffer.add_block(block):
                self.p2pFactory.send_block_to_peers(block, peer_identity)
        else:
            if chain_buffer_height + 1 == blocknumber:
                if blocknumber > 1 and self.chain.block_chain_buffer.add_block(block):
                    self.p2pFactory.send_block_to_peers(block, peer_identity)
                elif blocknumber == 1 and self.chain.block_chain_buffer.add_block_mainchain(block):
                    self.p2pFactory.send_block_to_peers(block, peer_identity)
                self.update_node_state('synced')
            else:
                self.chain.block_chain_buffer.add_pending_block(block)

        if self.nodeState.state == 'synced':
            if chain_buffer_height + 1 == blocknumber:
                self.last_pos_cycle = time.time()
                block_timestamp = int(block.blockheader.timestamp)
                curr_time = int(self.ntp.getTime())
                delay = c.POS_delay_after_block - min(c.POS_delay_after_block, max(0, curr_time - block_timestamp))

                self.restart_post_block_logic(delay)
        # commented
        '''
        if chain.m_blockchain and block.blockheader.epoch == curr_epoch or block.blockheader.epoch == next_epoch:
            if blocknumber < chain.height() + 1 and headerhash != chain.m_blockchain[blocknumber].blockheader.headerhash:
                if not chain.validate_block(block):
                    return False

                sum_block_reward_old_sl, sum_block_reward_new_sl = sumBlockReward(chain.m_blockchain[block.blockheader.blocknumber].blockheader.stake_selector, block.blockheader.stake_selector, block.blockheader.blocknumber)

                #Compare if strongest, then replace from the buffer
                total_stakers_new_block, score_new_block = getBlockStakeInfo(block, block_reward=sum_block_reward_new_sl)
                total_stakers, score = getBlockStakeInfo(chain.m_blockchain[blocknumber], block_reward=sum_block_reward_old_sl)
                printL (( 'New Block # ', blocknumber, ' HeaderHash: ', headerhash, ' Score: ', score_new_block, ' sum block reward : ', sum_block_reward_new_sl ))
                printL (( 'Old Block # ', blocknumber, ' HeaderHash: ', chain.m_blockchain[blocknumber].blockheader.headerhash, ' Score: ', score, ' sum block reward : ', sum_block_reward_old_sl ))
                printL (( str(chain.state_balance(block.blockheader.stake_selector)) ))
                if score_new_block < score:  #or total_stakers_new_block>total_stakers#Need to be reviewed
                    tmp_blocks = chain.m_blockchain[blocknumber:][::-1]
                    for tmp_block in tmp_blocks:
                        update_nonce(tmp_block)
                        txn_block_to_pool(tmp_block)
                        del chain.m_blockchain[tmp_block.blockheader.blocknumber]
                    add_block(block)
                    if chain.state.current == 'synced':
                        f.send_block_to_peers(block)

                return True

            if blocknumber == chain.height()+1 and prev_blockheaderhash == chain.m_blockchain[-1].blockheader.headerhash:
                if not chain.validate_block(block):
                    return False

                add_block(block)

                if chain.state.current == 'synced':
                    f.send_block_to_peers(block)
                if chain.state.current == 'unsynced':
                    chain.state.update('synced')
                restart_post_block_logic()
                return True
        '''
        return True

    def stop_post_block_logic(self, delay=0):
        try:
            reactor.post_block_logic.cancel()
            reactor.prepare_winners.cancel()
        except Exception:
            pass

    def restart_post_block_logic(self, delay=0):
        self.stop_post_block_logic()
        reactor.post_block_logic = reactor.callLater(delay,
                                                     self.post_block_logic)

    # post block logic we initiate the next POS cycle, send R1, send ST, reset POS flags and remove unnecessary messages in chain.stake_reveal_one and _two..

    def post_block_logic(self):
        self.filter_reveal_one_two()

        our_reveal = None
        blocknumber = self.chain.block_chain_buffer.height() + 1

        if self.p2pFactory.stake:
            tmp_stake_list = [
                s[0] for s in self.chain.block_chain_buffer.stake_list_get(blocknumber)
            ]
            if self.chain.mining_address in tmp_stake_list:
                our_reveal = self.p2pFactory.send_stake_reveal_one(blocknumber)
                self.schedule_prepare_winners(our_reveal, blocknumber - 1, 30)

            '''tmp_next_stake_list = [
                s[0] for s in self.chain.block_chain_buffer.next_stake_list_get(blocknumber)
            ]'''
            next_stake_list = self.chain.block_chain_buffer.next_stake_list_get(blocknumber)
            next_stake_first_hash = {}
            for s in next_stake_list:
                next_stake_first_hash[s[0]] = s[3]

            epoch = blocknumber // c.blocks_per_epoch
            epoch_blocknum = blocknumber - epoch * c.blocks_per_epoch

            if epoch_blocknum < c.stake_before_x_blocks and self.chain.mining_address not in next_stake_first_hash:
                diff = max(1, ((c.stake_before_x_blocks - epoch_blocknum + 1) * int(1 - c.st_txn_safety_margin)))
                if random.randint(1, diff) == 1:
                    self.make_st_tx(blocknumber, None)
            elif epoch_blocknum >= c.stake_before_x_blocks-1 and self.chain.mining_address in next_stake_first_hash:
                if next_stake_first_hash[self.chain.mining_address] is None:
                    threshold_blocknum = self.chain.state.get_staker_threshold_blocknum(next_stake_list,
                                                                                        self.chain.mining_address)
                    max_threshold_blocknum = c.blocks_per_epoch
                    if threshold_blocknum == c.low_staker_first_hash_block:
                        max_threshold_blocknum = c.high_staker_first_hash_block

                    if epoch_blocknum >= threshold_blocknum - 1 and epoch_blocknum < max_threshold_blocknum - 1:
                        diff = max(1, ((max_threshold_blocknum - epoch_blocknum + 1)*int(1-c.st_txn_safety_margin)) )
                        if random.randint(1, diff) == 1:
                            my = deepcopy(self.chain.my[0][1])
                            my.hashchain(epoch=epoch+1)
                            self.make_st_tx(blocknumber, my.hc[-1][-2])

        return

    def make_st_tx(self, blocknumber, first_hash):
        balance = self.chain.state.state_balance(self.chain.mining_address)
        if balance < c.minimum_staking_balance_required:
            printL (( 'Staking not allowed due to insufficient balance'))
            printL (( 'Balance ', balance))
            return

        st = StakeTransaction().create_stake_transaction(
            self.chain.mining_address, blocknumber,
            self.chain.my[0][1],
            first_hash = first_hash,
            balance = balance
        )
        self.p2pFactory.send_st_to_peers(st)
        self.chain.wallet.f_save_winfo()
        for num in range(len(self.chain.stake_pool)):
            t = self.chain.stake_pool[num]
            if st.hash == t.hash:
                if st.get_message_hash() == t.get_message_hash():
                    return
                del self.chain.stake_pool[num]
                break

        self.chain.stake_pool.append(st)
        '''
        for t in self.chain.stake_pool:
            if st.hash == t.hash:
                if st.get_message_hash() != t.get_message_hash():
                    t.first_hash = st.first_hash
                return
        self.chain.add_st_to_pool(st)
        '''

    def schedule_prepare_winners(self, our_reveal, last_block_number, delay=0):
        try:
            reactor.prepare_winners.cancel()
        except:
            pass
        reactor.prepare_winners = reactor.callLater(
            delay,
            self.prepare_winners,
            our_reveal=our_reveal,
            last_block_number=last_block_number)

    def prepare_winners(self, our_reveal, last_block_number):
        if not self.nodeState.state == 'synced':
            return
        filtered_reveal_one = []
        reveals = []
        vote_hashes = []
        next_block_num = last_block_number + 1
        for s in self.chain.stake_reveal_one:
            tmp_strongest_headerhash = self.chain.block_chain_buffer.get_strongest_headerhash(last_block_number)
            if s[1] == tmp_strongest_headerhash and s[2] == next_block_num:
                filtered_reveal_one.append(s)
                reveals.append(s[3])
                vote_hashes.append(s[5])

        self.restart_post_block_logic(30)

        if len(filtered_reveal_one) <= 1:
            printL(('only received one reveal for this block.. blocknum #', next_block_num))
            return

        epoch = (next_block_num) / c.blocks_per_epoch  # +1 = next block
        seed = self.chain.block_chain_buffer.get_epoch_seed(next_block_num)
        winners = self.chain.select_winners(filtered_reveal_one,
                                            topN=3,
                                            seed=seed)

        # reactor.process_blocks = reactor.callLater(30, process_blocks, winners=winners, our_reveal=our_reveal)

        if not (self.p2pFactory.stake and our_reveal):
            return

        if our_reveal in winners:
            block = self.create_new_block(our_reveal,
                                          reveals,
                                          vote_hashes,
                                          last_block_number)
            self.pre_block_logic(block)  # broadcast this block

        if self.chain.pending_tx_pool:
            if len(self.chain.transaction_pool) < 10:
                printL(('Processing TXNs if any'))
                self.process_transactions(5)

    def randomize_block_fetch(self, blocknumber):
        if self.nodeState.state != 'syncing' or blocknumber <= self.chain.height():
            return

        if len(self.p2pFactory.target_peers.keys()) == 0:
            printL((' No target peers found.. stopping download'))
            return

        reactor.download_monitor = reactor.callLater(20,
                                                     self.randomize_block_fetch, blocknumber)

        random_peer = self.p2pFactory.target_peers[random.choice(self.p2pFactory.target_peers.keys())]
        random_peer.fetch_block_n(blocknumber)

    def randomize_headerhash_fetch(self, block_number):
        if self.nodeState.state != 'forked':
            return
        if block_number not in fork.pending_blocks or fork.pending_blocks[block_number][1] <= 10:  # retry only 11 times
            headerhash_monitor = reactor.callLater(15, self.randomize_headerhash_fetch, block_number)
            if len(self.p2pFactory.peers) > 0:
                try:
                    if len(self.p2pFactory.fork_target_peers) == 0:
                        for peer in self.p2pFactory.peers:
                            self.p2pFactory.fork_target_peers[peer.identity] = peer
                    if len(self.p2pFactory.fork_target_peers) > 0:
                        random_peer = self.p2pFactory.fork_target_peers[
                            random.choice(
                                self.p2pFactory.fork_target_peers.keys()
                            )
                        ]
                        count = 0
                        if block_number in fork.pending_blocks:
                            count = fork.pending_blocks[block_number][1] + 1
                        fork.pending_blocks[block_number] = [
                            random_peer.identity, count, None, headerhash_monitor
                        ]
                        random_peer.fetch_headerhash_n(block_number)
                except:
                    printL(('Exception at randomize_headerhash_fetch'))
            else:
                printL(('No peers connected.. Will try again... randomize_headerhash_fetch: ', block_number))
        else:
            self.update_node_state('unsynced')

    # blockheight map for connected nodes - when the blockheight seems up to date after a sync or error, we check all connected nodes to ensure all on same chain/height..
    # note - may not return correctly during a block propagation..
    # once working alter to identify fork better..

    def blockheight_map(self):

        # i = [block_number, headerhash, self.transport.getPeer().host]

        printL(('blockheight_map:'))
        printL((self.chain.blockheight_map))

        # first strip out any laggards..
        self.chain.blockheight_map = filter(
            lambda s: s[0] >= self.chain.m_blockheight(),
            self.chain.blockheight_map
        )

        result = True

        # next identify any node entries which are not exactly correct..

        for s in self.chain.blockheight_map:
            if s[0] == self.chain.m_blockheight():
                if s[1] == self.chain.m_blockchain[-1].blockheader.headerhash:
                    printL(('node: ', s[2], '@', s[0], 'w/:', s[1], 'OK'))
            elif s[0] > self.chain.m_blockheight():
                printL(('warning..', s[2], 'at blockheight', s[0]))
                result = False

        # wipe it..

        del self.chain.blockheight_map[:]

        return result


class P2PProtocol(Protocol):
    def __init__(self):
        self.service = {'reboot': self.reboot,
                        'MR': self.MR,
                        # 'RFM': self.RFM, only for internal usage
                        'SFM': self.SFM,
                        'TX': self.TX,
                        'ST': self.ST,
                        'BM': self.BM,
                        'BK': self.BK,
                        'PBB': self.PBB,
                        'PB': self.PB,
                        'PH': self.PH,
                        'LB': self.LB,
                        'FMBH': self.FMBH,
                        'PMBH': self.PMBH,
                        'MB': self.MB,
                        'CB': self.CB,
                        'BN': self.BN,
                        'FB': self.FB,
                        'FH': self.FH,
                        'PO': self.PO,
                        'PI': self.PI,
                        'PL': self.PL,
                        'RT': self.RT,
                        'PE': self.PE,
                        'VE': self.VE,
                        'R1': self.R1,
                        'IP': self.IP,
                        }
        self.buffer = ''
        self.messages = []
        self.identity = None
        self.blockheight = None
        self.version = ''
        self.blocknumber_headerhash = {}
        self.last_requested_blocknum = None
        self.fetch_tried = 0
        pass

    def parse_msg(self, data):
        try:
            jdata = json.loads(data)
        except:
            return

        func = jdata['type']

        if func not in self.service:
            return

        func = self.service[func]
        try:
            if 'data' in jdata:
                func(jdata['data'])
            else:
                func()
        except:
            printL(("parse_msg Exception while calling "))
            printL(("Func name ", func))
            # printL (( "JSON data ", jdata ))
            pass

    def reboot(self, data):
        hash_dict = json.loads(data)
        if not ('hash' in hash_dict and 'nonce' in hash_dict):
            return
        if not self.factory.chain.validate_reboot(hash_dict['hash'], hash_dict['nonce']):
            return
        for peer in self.factory.peers:
            if peer != self:
                peer.transport.write(self.wrap_message('reboot', data))
        printL(('Initiating Reboot Sequence.....'))

        self.update_node_state('synced')

    def MR(self, data):
        data = json.loads(data)
        if data['type'] not in MessageReceipt.allowed_types:
            return

        if data['type'] in ['R1', 'ST', 'TX'] and self.factory.nodeState.state != 'synced':
            return

        if self.factory.master_mr.peer_contains_hash(data['hash'], data['type'], self):
            return

        self.factory.master_mr.add(data['hash'], data['type'], self)

        if data['hash'] in self.factory.master_mr.hash_callLater:   # Ignore if already requested
            return

        if self.factory.master_mr.contains(data['hash'], data['type']):
            return

        self.RFM(data)

    def RFM(self, data):  # Request full message, Move to factory
        msg_hash = data['hash']
        if msg_hash in self.factory.master_mr.hash_msg:
            if msg_hash in self.factory.master_mr.hash_callLater:
                del self.factory.master_mr.hash_callLater[msg_hash]
            return
        for peer in self.factory.master_mr.hash_peer[msg_hash]:
            if peer not in self.factory.master_mr.requested_hash[msg_hash]:
                self.factory.master_mr.requested_hash[msg_hash].append(peer)
                peer.transport.write(self.wrap_message('SFM', helper.json_encode(data)))
                call_later_obj = reactor.callLater(c.message_receipt_timeout,
                                                   self.RFM,
                                                   data)
                self.factory.master_mr.hash_callLater[msg_hash] = call_later_obj
                return

        # If executing reach to this line, then it means no peer was able to provide
        # Full message for this hash thus the hash has to be deleted.
        # Moreover, negative points could be added to the peers, for this behavior
        if msg_hash in self.factory.master_mr.hash_callLater:
            del self.factory.master_mr.hash_callLater[msg_hash]

    def SFM(self, data):  # Send full message
        data = json.loads(data)
        msg_hash = data['hash']
        msg_type = data['type']
        if not self.factory.master_mr.contains(msg_hash, msg_type):
            return

        # Sending message from node, doesn't guarantee that peer has received it.
        # Thus requesting peer could re request it, may be ACK would be required
        # To confirm, if the peer has received, otherwise X number of maximum retry
        # if self.factory.master_mr.peer_contains_hash(msg_hash, msg_type, self):
        #    return

        self.transport.write(self.wrap_message(msg_type,
                                               self.factory.master_mr.hash_msg[msg_hash]))

        self.factory.master_mr.add(msg_hash, msg_type, self)

    def broadcast(self, msg_hash, msg_type):  # Move to factory
        data = {}
        data['hash'] = sha256(str(msg_hash))
        data['type'] = msg_type
        for peer in self.factory.peers:
            if peer not in self.factory.master_mr.hash_peer[data['hash']]:
                peer.transport.write(self.wrap_message('MR', helper.json_encode(data)))

    def TX(self, data):  # tx received..
        self.recv_tx(data)
        return

    def ST(self, data):
        try:
            st = StakeTransaction().json_to_transaction(data)
        except:
            printL(('st rejected - unable to decode serialised data - closing connection'))
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(st.get_message_hash(), self):
            return
        #printL (( 'Received ST Transaction with', st.txfrom, st.first_hash, st.epoch ))
        '''
        for t in self.factory.chain.stake_pool:  # duplicate tx already received, would mess up nonce..
            if st.hash == t.hash:
                if t.first_hash:
                    return
                if not st.first_hash:
                    return
                blocknumber = self.factory.chain.block_chain_buffer.height() + 1
                next_stake_list = self.factory.chain.block_chain_buffer.next_stake_list_get(blocknumber)
                threshold_blocknum = self.factory.chain.state.get_staker_threshold_blocknum(next_stake_list,
                                                                                    self.factory.chain.mining_address)
                epoch = blocknumber // c.blocks_per_epoch
                epoch_blocknum = blocknumber - epoch * c.blocks_per_epoch

                if epoch_blocknum < threshold_blocknum - 1:
                    return

                if st.validate_tx() and st.state_validate_tx(state=self.factory.chain.state):
                    t.first_hash = st.first_hash
                    self.factory.master_mr.register(st.get_message_hash(), st.transaction_to_json(), 'ST')
                    self.broadcast(st.get_message_hash(), 'ST')

                return
        '''
        for t in self.factory.chain.stake_pool:
            if st.get_message_hash() == t.get_message_hash():
                return

        if st.validate_tx() and st.state_validate_tx(state=self.factory.chain.state):
            self.factory.chain.add_st_to_pool(st)
        else:
            printL(('>>>ST', st.hash,
                    'invalid state validation failed..'))  # ' invalid - closing connection to ', self.transport.getPeer().host
            return

        self.factory.master_mr.register(st.get_message_hash(), st.transaction_to_json(), 'ST')
        self.broadcast(st.get_message_hash(), 'ST')
        return

    def BM(self, data=None):  # blockheight map for synchronisation and error correction prior to POS cycle resync..
        if not data:
            printL(('<<<Sending block_map', self.transport.getPeer().host))
            z = {}
            z['block_number'] = self.factory.chain.m_blockchain[-1].blockheader.blocknumber
            z['headerhash'] = self.factory.chain.m_blockchain[-1].blockheader.headerhash
            self.transport.write(self.wrap_message('BM', helper.json_encode(z)))
            return
        else:
            printL(('>>>Receiving block_map'))
            z = helper.json_decode(data)
            block_number = z['block_number']
            headerhash = z['headerhash'].encode('latin1')

            i = [block_number, headerhash, self.transport.getPeer().host]
            printL((i))
            if i not in self.factory.chain.blockheight_map:
                self.factory.chain.blockheight_map.append(i)
            return

    def BK(self, data):  # block received
        try:
            block = helper.json_decode_block(data)
        except:
            printL(('block rejected - unable to decode serialised data', self.transport.getPeer().host))
            return
        printL(('>>>Received block from ', self.identity, block.blockheader.blocknumber, block.blockheader.stake_selector))
        if not self.factory.master_mr.isRequested(block.blockheader.headerhash, self):
            return

        self.factory.pos.pre_block_logic(block, self.identity)
        self.factory.master_mr.register(block.blockheader.headerhash, data, 'BK')
        self.broadcast(block.blockheader.headerhash, 'BK')
        return

    def isNoMoreBlock(self, data):
        if type(data) == int:
            blocknumber = data
            if blocknumber != self.last_requested_blocknum:
                return True
            try:
                reactor.download_monitor.cancel()
            except:
                pass
            self.factory.pos.update_node_state('synced')
            return True
        return False

    def PBB(self, data):
        self.factory.pos.last_pb_time = time.time()
        try:
            if self.isNoMoreBlock(data):
                return

            data = helper.json_decode(data)
            blocknumber = int(data.keys()[0].encode('ascii'))

            if blocknumber != self.last_requested_blocknum:
                printL(('Blocknumber not found in pending_blocks', blocknumber, self.identity))
                return

            for jsonBlock in data[unicode(blocknumber)]:
                block = helper.json_decode_block(json.dumps(jsonBlock))
                printL(('>>>Received Block #', block.blockheader.blocknumber))

                status = self.factory.chain.block_chain_buffer.add_block(block)
                if type(status) == bool and not status:
                    printL(("[PBB] Failed to add block by add_block, re-requesting the block #", blocknumber))
                    printL(('Skipping one block'))
                    continue

            try:
                reactor.download_block.cancel()
            except Exception:
                pass

            # Below code is to stop downloading, once we see that we reached to blocknumber that are in pending_blocks
            # This could be exploited by sybil node, to send blocks in pending_blocks in order to disrupt downloading
            # TODO: required a better fix
            if len(self.factory.chain.block_chain_buffer.pending_blocks) > 0 and min(
                    self.factory.chain.block_chain_buffer.pending_blocks.keys()) == blocknumber:
                self.factory.chain.block_chain_buffer.process_pending_blocks()
                return
            self.factory.pos.randomize_block_fetch(blocknumber + 1)
        except KeyboardInterrupt:
            printL(('.block rejected - unable to decode serialised data', self.transport.getPeer().host))
            return

    def PB(self, data):
        self.factory.pos.last_pb_time = time.time()
        try:
            if self.isNoMoreBlock(data):
                return

            block = helper.json_decode_block(data)
            blocknumber = block.blockheader.blocknumber
            printL(('>>>Received Block #', blocknumber))
            if blocknumber != self.last_requested_blocknum:
                printL(('Didnt match', self.last_requested_blocknum, thisPeerHost.host, thisPeerHost.port))
                return

            if blocknumber > self.factory.chain.height():
                if not self.factory.chain.block_chain_buffer.add_block_mainchain(block):
                    printL(('PB failed to add block to mainchain'))
                    return

            try:
                reactor.download_monitor.cancel()
            except Exception:
                pass

            self.factory.pos.randomize_block_fetch(blocknumber + 1)

        except KeyboardInterrupt:
            printL(('.block rejected - unable to decode serialised data', self.transport.getPeer().host))
        return

    def PH(self, data):
        if self.factory.nodeState.state == 'forked':
            fork.verify(data, self.identity, chain, randomize_headerhash_fetch)
        else:
            mini_block = json.loads(data)
            self.blocknumber_headerhash[mini_block['blocknumber']] = mini_block['headerhash']

    def LB(self):  # request for last block to be sent
        printL(('<<<Sending last block', str(self.factory.chain.m_blockheight()),
                str(len(helper.json_bytestream(self.factory.chain.m_get_last_block()))), ' bytes', 'to node: ',
                self.transport.getPeer().host))
        self.transport.write(self.wrap_message('BK', helper.json_bytestream_bk(self.factory.chain.m_get_last_block())))
        return

    def FMBH(self):  # Fetch Maximum Blockheight and Headerhash
        if self.factory.pos.nodeState.state != 'synced':
            return
        printL(('<<<Sending blockheight and headerhash to: ', self.transport.getPeer().host, str(time.time())))
        data = {}
        data['headerhash'] = self.factory.chain.m_blockchain[-1].blockheader.headerhash
        data['blocknumber'] = self.factory.chain.m_blockchain[-1].blockheader.blocknumber
        self.transport.write(self.wrap_message('PMBH', helper.json_encode(data)))

    def PMBH(self, data):  # Push Maximum Blockheight and Headerhash
        data = helper.json_decode(data)
        if not data or 'headerhash' not in data or 'blocknumber' not in data:
            return

        if self.identity in self.factory.pos.fmbh_allowed_peers:
            self.factory.pos.fmbh_allowed_peers[self.identity] = data
            if data['headerhash'] not in self.factory.pos.fmbh_blockhash_peers:
                self.factory.pos.fmbh_blockhash_peers[data['headerhash']] = {'blocknumber': data['blocknumber'],
                                                                             'peers': []}
            self.factory.pos.fmbh_blockhash_peers[data['headerhash']]['peers'].append(self)

    def MB(self):  # we send with just prefix as request..with CB number and blockhash as answer..
        printL(('<<<Sending blockheight to:', self.transport.getPeer().host, str(time.time())))
        self.send_m_blockheight_to_peer()
        return

    def CB(self, data):
        z = helper.json_decode(data)
        block_number = z['block_number']
        headerhash = z['headerhash'].encode('latin1')

        self.blockheight = block_number

        printL(('>>>Blockheight from:', self.transport.getPeer().host, 'blockheight: ', block_number,
                'local blockheight: ', str(self.factory.chain.m_blockheight()), str(time.time())))

        self.factory.peers_blockheight[self.transport.getPeer().host + ':' + str(self.transport.getPeer().port)] = z[
            'block_number']

        if self.factory.nodeState.state == 'syncing': return

        if block_number == self.factory.chain.m_blockheight():
            if self.factory.chain.m_blockchain[block_number].blockheader.headerhash != headerhash:
                printL(('>>> WARNING: headerhash mismatch from ', self.transport.getPeer().host))

                # initiate fork recovery and protection code here..
                # call an outer function which sets a flag and scrutinises the chains from all connected hosts to see what is going on..
                # again need to think this one through in detail..

                return

        if block_number > self.factory.chain.m_blockheight():
            return

        if len(self.factory.chain.m_blockchain) == 1 and self.factory.genesis == 0:
            self.factory.genesis = 1  # set the flag so that no other Protocol instances trigger the genesis stake functions..
            printL(('genesis pos countdown to block 1 begun, 60s until stake tx circulated..'))
            reactor.callLater(1, self.factory.pos.pre_pos_1)
            return

        elif len(
                self.factory.chain.m_blockchain) == 1 and self.factory.genesis == 1:  # connected to multiple hosts and already passed through..
            return

    def BN(self, data):  # request for block (n)
        if int(data) <= self.factory.chain.m_blockheight():
            printL(('<<<Sending block number', str(int(data)),
                    str(len(helper.json_bytestream(self.factory.chain.m_get_block(int(data))))), ' bytes', 'to node: ',
                    self.transport.getPeer().host))
            self.transport.write(
                self.wrap_message('BK', helper.json_bytestream_bk(self.factory.chain.m_get_block(int(data)))))
            return
        else:
            if int(data) >= self.factory.chain.m_blockheight():
                printL(('BN for a blockheight greater than local chain length..'))
                return
            else:
                printL(('BN request without valid block number', data, '- closing connection'))
                self.transport.loseConnection()
                return

    def FB(self, data):  # Fetch Request for block
        data = int(data)
        printL((' Reqeust for ', data, ' by ', self.identity))
        if data > 0 and data <= self.factory.chain.block_chain_buffer.height():
            self.factory.chain.block_chain_buffer.send_block(data, self.transport, self.wrap_message)
        else:
            self.transport.write(self.wrap_message('PB', data))
            if data > self.factory.chain.height():
                printL(('FB for a blocknumber is greater than the local chain length..'))
                return

    def FH(self, data):  # Fetch Block Headerhash
        data = int(data)
        if data > 0 and data <= self.factory.chain.height():
            mini_block = {}
            printL(('<<<Pushing block headerhash of block number ', str(data), ' to node: ',
                    self.transport.getPeer().host))
            mini_block['headerhash'] = self.factory.chain.m_get_block(data).blockheader.headerhash
            mini_block['blocknumber'] = data
            self.transport.write(self.wrap_message('PH', helper.json_bytestream_ph(mini_block)))
        else:
            if data > self.factory.chain.height():
                printL(('FH for a blocknumber is greater than the local chain length..'))
                return

    def PO(self, data):
        if data[0:2] == 'NG':
            y = 0
            for entry in self.factory.chain.ping_list:
                if entry['node'] == self.transport.getPeer().host:
                    entry['ping (ms)'] = (time.time() - chain.last_ping) * 1000
                    y = 1
            if y == 0:
                self.factory.chain.ping_list.append({'node': self.transport.getPeer().host,
                                                     'ping (ms)': (time.time() - self.factory.chain.last_ping) * 1000})

    def PI(self, data):
        if data[0:2] == 'NG':
            self.transport.write(self.wrap_message('PONG'))
        else:
            self.transport.loseConnection()
            return

    def PL(self, data):  # receiving a list of peers to save into peer list..
        self.recv_peers(data)

    def RT(self):
        '<<< Transaction_pool to peer..'
        for t in self.factory.chain.transaction_pool:
            f.send_tx_to_peers(t)
        return

    def PE(self):  # get a list of connected peers..need to add some ddos and type checking proteection here..
        self.get_peers()

    def VE(self, data=None):
        if not data:
            self.transport.write(self.wrap_message('VE', self.factory.chain.version_number))
        else:
            self.version = str(data)
            printL((self.transport.getPeer().host, 'version: ', data))
        return

    # receive a reveal_one message sent out after block receipt or creation (could be here prior to the block!)
    def R1(self, data):
        if self.factory.nodeState.state != 'synced':
            return
        z = json.loads(data, parse_float=Decimal)
        if not z:
            return
        block_number = z['block_number']
        headerhash = z['headerhash'].encode('latin1')
        stake_address = z['stake_address'].encode('latin1')
        vote_hash = z['vote_hash'].encode('latin1')
        reveal_one = z['reveal_one'].encode('latin1')

        if not self.factory.master_mr.isRequested(z['vote_hash'], self):
            return

        if block_number <= self.factory.chain.height():
            return

        for entry in self.factory.chain.stake_reveal_one:  # already received, do not relay.
            if entry[3] == reveal_one:
                return

        if len(self.factory.chain.stake_validator_latency) > 20:
            del self.factory.chain.stake_validator_latency[min(self.factory.chain.stake_validator_latency.keys())]

        y = 0
        if self.factory.nodeState.epoch_diff == 0:
            for s in self.factory.chain.block_chain_buffer.stake_list_get(z['block_number']):
                if s[0] == stake_address:
                    y = 1
                    # +1 as one of the hash is already revealed at start
                    reveal_one_tmp = self.factory.chain.reveal_to_terminator(reveal_one, block_number, 1)
                    vote_hash_tmp = self.factory.chain.reveal_to_terminator(vote_hash, block_number)
                    reveal_hash_terminator, vote_hash_terminator = self.factory.chain.select_hashchain(
                        last_block_headerhash=self.factory.chain.block_chain_buffer.get_strongest_headerhash(
                            block_number - 1), stake_address=stake_address, blocknumber=z['block_number'])
                    if vote_hash_tmp != vote_hash_terminator:
                        printL((self.identity, ' vote hash doesnt hash to stake terminator', 'vote', vote_hash, 'nonce',
                                s[2], 'vote_hash', vote_hash_terminator))
                        return
                    if reveal_one_tmp != reveal_hash_terminator:
                        printL((self.identity, ' reveal doesnt hash to stake terminator', 'reveal', reveal_one, 'nonce',
                                s[2], 'reveal_hash', reveal_hash_terminator))
                        return
            if y == 0:
                printL(('stake address not in the stake_list'))
                return

        if len(self.factory.pos.r1_time_diff) > 2:
            del self.factory.pos.r1_time_diff[min(self.factory.pos.r1_time_diff.keys())]

        self.factory.pos.r1_time_diff[block_number].append(int(time.time() * 1000))

        printL(('>>> POS reveal_one:', self.transport.getPeer().host, stake_address, str(block_number), reveal_one))
        score = self.factory.chain.score(stake_address=stake_address,
                                         reveal_one=reveal_one,
                                         balance=self.factory.chain.block_chain_buffer.get_st_balance(stake_address, block_number),
                                         seed=z['seed'])

        if score == None:
            printL(('Score None for stake_address ', stake_address, ' reveal_one ', reveal_one))
            return

        if score != z['weighted_hash']:
            printL(('Weighted_hash didnt match'))
            printL(('Expected : ', str(score)))
            printL(('Found : ', str(z['weighted_hash'])))
            printL(('Seed found : ', str(z['seed']) ))
            printL(('Seed Expected : ', str(str(self.factory.chain.block_chain_buffer.get_epoch_seed(z['block_number'])))))
            printL(('Balance : ', self.factory.chain.block_chain_buffer.get_st_balance(stake_address, block_number)))

            return

        epoch = block_number // c.blocks_per_epoch
        epoch_seed = self.factory.chain.block_chain_buffer.get_epoch_seed(z['block_number'])


        if epoch_seed != z['seed']:
            printL(('Seed didnt match'))
            printL(('Expected : ', str(epoch_seed)))
            printL(('Found : ', str(z['seed'])))
            return

        sv_hash = self.factory.chain.get_stake_validators_hash()
        # if sv_hash != z['SV_hash']:
        #	printL (( 'SV_hash didnt match' ))
        #	printL (( 'Expected : ', sv_hash ))
        #	printL (( 'Found : ', z['SV_hash'] ))
        #	return

        self.factory.chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one, score, vote_hash])
        self.factory.master_mr.register(z['vote_hash'], data, 'R1')
        if self.factory.nodeState.state == 'synced':
            self.broadcast(z['vote_hash'], 'R1')
            #for peer in self.factory.peers:
            #    if peer != self:
            #        peer.transport.write(self.wrap_message('R1', helper.json_encode(z)))  # relay

        return

    def IP(self, data):  # fun feature to allow geo-tagging on qrl explorer of test nodes..reveals IP so optional..
        if not data:
            if self.factory.ip_geotag == 1:
                for peer in self.factory.peers:
                    if peer != self:
                        peer.transport.write(self.wrap_message('IP', self.transport.getHost().host))
        else:
            if data not in self.factory.chain.ip_list:
                self.factory.chain.ip_list.append(data)
                for peer in self.factory.peers:
                    if peer != self:
                        peer.transport.write(self.wrap_message('IP', self.transport.getHost().host))

        return

    def recv_peers(self, json_data):
        if not c.enable_peer_discovery:
            return
        data = helper.json_decode(json_data)
        new_ips = []
        for ip in data:
            if ip not in new_ips:
                new_ips.append(ip.encode('latin1'))
        peers_list = self.factory.chain.state.state_get_peers()
        printL((self.transport.getPeer().host, 'peers data received: ', new_ips))
        for node in new_ips:
            if node not in peers_list:
                if node != self.transport.getHost().host:
                    peers_list.append(node)
                    reactor.connectTCP(node, 9000, self.factory)
        self.factory.chain.state.state_put_peers(peers_list)
        self.factory.chain.state.state_save_peers()
        return

    def get_latest_block_from_connection(self):
        printL(('<<<Requested last block from', self.transport.getPeer().host))
        self.transport.write(self.wrap_message('LB'))
        return

    def get_m_blockheight_from_connection(self):
        printL(('<<<Requesting blockheight from', self.transport.getPeer().host))
        self.transport.write(self.wrap_message('MB'))
        return

    def send_m_blockheight_to_peer(self):
        z = {}
        z['headerhash'] = self.factory.chain.m_blockchain[-1].blockheader.headerhash
        z['block_number'] = 0
        if len(self.factory.chain.m_blockchain):
            z['block_number'] = self.factory.chain.m_blockchain[-1].blockheader.blocknumber
        self.transport.write(self.wrap_message('CB', helper.json_encode(z)))
        return

    def get_version(self):
        printL(('<<<Getting version', self.transport.getPeer().host))
        self.transport.write(self.wrap_message('VE'))
        return

    def get_peers(self):
        printL(('<<<Sending connected peers to', self.transport.getPeer().host))
        peers_list = []
        for peer in self.factory.peers:
            peers_list.append(peer.transport.getPeer().host)
        self.transport.write(self.wrap_message('PL', helper.json_encode(peers_list)))
        return

    def get_block_n(self, n):
        printL(('<<<Requested block: ', str(n), 'from ', self.transport.getPeer().host))
        self.transport.write(self.wrap_message('BN', str(n)))
        return

    def fetch_block_n(self, n):
        if self.last_requested_blocknum != n:
            self.fetch_tried = 0
        self.fetch_tried += 1  # TODO: remove from target_peers if tried is greater than x
        self.last_requested_blocknum = n
        printL(('<<<Fetching block: ', n, 'from ', self.transport.getPeer().host, ':', self.transport.getPeer().port))
        self.transport.write(self.wrap_message('FB', str(n)))
        return

    def fetch_FMBH(self):
        printL(('<<<Fetching FMBH from : ', self.identity))
        self.transport.write(self.wrap_message('FMBH'))

    def fetch_headerhash_n(self, n):
        printL(('<<<Fetching headerhash of block: ', n, 'from ', self.transport.getPeer().host, ':',
                self.transport.getPeer().port))
        self.transport.write(self.wrap_message('FH', str(n)))
        return

    def wrap_message(self, type, data=None):
        jdata = {}
        jdata['type'] = type
        if data:
            jdata['data'] = data
        str_data = json.dumps(jdata)
        return chr(255) + chr(0) + chr(0) + struct.pack('>L', len(str_data)) + chr(0) + str_data + chr(0) + chr(
            0) + chr(255)

    def clean_buffer(self, reason=None, upto=None):
        if reason:
            printL((reason))
        if upto:
            self.buffer = self.buffer[upto:]  # Clean buffer till the value provided in upto
        else:
            self.buffer = ''  # Clean buffer completely

    def parse_buffer(self):
        if len(self.buffer) == 0:
            return False

        d = self.buffer.find(chr(255) + chr(0) + chr(0))  # find the initiator sequence
        num_d = self.buffer.count(chr(255) + chr(0) + chr(0))  # count the initiator sequences

        if d == -1:  # if no initiator sequences found then wipe buffer..
            self.clean_buffer(reason='Message data without initiator')
            return False

        self.buffer = self.buffer[d:]  # delete data up to initiator

        if len(self.buffer) < 8:  # Buffer is still incomplete as it doesn't have message size
            return False

        try:
            m = struct.unpack('>L', self.buffer[3:7])[0]  # is m length encoded correctly?
        except:
            if num_d > 1:  # if not, is this the only initiator in the buffer?
                self.buffer = self.buffer[3:]
                d = self.buffer.find(chr(255) + chr(0) + chr(0))
                self.clean_buffer(reason='Struct.unpack error attempting to decipher msg length, next msg preserved',
                                  upto=d)  # no
                return True
            else:
                self.clean_buffer(reason='Struct.unpack error attempting to decipher msg length..')  # yes
            return False

        if m > c.message_buffer_size:  # check if size is more than 500 KB
            if num_d > 1:
                self.buffer = self.buffer[3:]
                d = self.buffer.find(chr(255) + chr(0) + chr(0))
                self.clean_buffer(reason='Size is more than 500 KB, next msg preserved', upto=d)
                return True
            else:
                self.clean_buffer(reason='Size is more than 500 KB')
            return False

        e = self.buffer.find(chr(0) + chr(0) + chr(255))  # find the terminator sequence

        if e == -1:  # no terminator sequence found
            if len(self.buffer) > 8 + m + 3:
                if num_d > 1:  # if not is this the only initiator sequence?
                    self.buffer = self.buffer[3:]
                    d = self.buffer.find(chr(255) + chr(0) + chr(0))
                    self.clean_buffer(reason='Message without appropriate terminator, next msg preserved', upto=d)  # no
                    return True
                else:
                    self.clean_buffer(reason='Message without initiator and terminator')  # yes
            return False

        if e != 3 + 5 + m:  # is terminator sequence located correctly?
            if num_d > 1:  # if not is this the only initiator sequence?
                self.buffer = self.buffer[3:]
                d = self.buffer.find(chr(255) + chr(0) + chr(0))
                self.clean_buffer(reason='Message terminator incorrectly positioned, next msg preserved', upto=d)  # no
                return True
            else:
                self.clean_buffer(reason='Message terminator incorrectly positioned')  # yes
            return False

        self.messages.append(self.buffer[8:8 + m])  # if survived the above then save the msg into the self.messages
        self.buffer = self.buffer[8 + m + 3:]  # reset the buffer to after the msg
        return True

    def dataReceived(self, data):  # adds data received to buffer. then tries to parse the buffer twice..

        self.buffer += data

        for x in range(50):
            if self.parse_buffer() == False:
                break
            else:
                for msg in self.messages:
                    self.parse_msg(msg)
                del self.messages[:]
        return

    def connectionMade(self):
        peerHost, peerPort = self.transport.getPeer().host, self.transport.getPeer().port
        self.identity = peerHost + ":" + str(peerPort)
        #For AWS
        if c.public_ip:
            if self.transport.getPeer().host == c.public_ip:
                self.transport.loseConnection()
                return
        if len(self.factory.peers) >= c.max_peers_limit:
            printL (( 'Peer limit hit '))
            printL (( '# of Connected peers ', len(self.factory.peers) ))
            printL (( 'Peer Limit ', c.peer_list))
            printL (( 'Disconnecting client ', self.identity))
            self.transport.loseConnection()
            return

        self.factory.connections += 1
        self.factory.peers.append(self)
        peer_list = self.factory.chain.state.state_get_peers()
        if self.transport.getPeer().host == self.transport.getHost().host:
            if self.transport.getPeer().host in peer_list:
                printL(('Self in peer_list, removing..'))
                peer_list.remove(self.transport.getPeer().host)
                self.factory.chain.state.state_put_peers(peer_list)
                self.factory.chain.state.state_save_peers()
            self.transport.loseConnection()
            return

        if self.transport.getPeer().host not in peer_list:
            printL(('Adding to peer_list'))
            peer_list.append(self.transport.getPeer().host)
            self.factory.chain.state.state_put_peers(peer_list)
            self.factory.chain.state.state_save_peers()
        printL(('>>> new peer connection :', self.transport.getPeer().host, ' : ', str(self.transport.getPeer().port)))

        self.get_m_blockheight_from_connection()
        self.get_peers()
        self.get_version()

    # here goes the code for handshake..using functions within the p2pprotocol class
    # should ask for latest block/block number.

    def connectionLost(self, reason):
        printL((self.transport.getPeer().host, ' disconnected. ', 'remainder connected: ',
                str(self.factory.connections)))  # , reason
        try:
            self.factory.peers.remove(self)
            self.factory.connections -= 1

            if self.identity in self.factory.target_peers:
                del self.factory.target_peers[self.identity]
            host_port = self.transport.getPeer().host + ':' + str(self.transport.getPeer().port)
            if host_port in self.factory.peers_blockheight:
                del self.factory.peers_blockheight[host_port]
            if self.factory.connections == 0:
                reactor.callLater(60, self.factory.connect_peers)
        except Exception:
            pass

    def recv_tx(self, json_tx_obj):

        try:
            tx = SimpleTransaction().json_to_transaction(json_tx_obj)
        except:
            printL(('tx rejected - unable to decode serialised data - closing connection'))
            self.transport.loseConnection()
            return

        if not self.factory.master_mr.isRequested(tx.get_message_hash(), self):
            return

        if tx.txhash in self.factory.chain.prev_txpool or tx.txhash in self.factory.chain.pending_tx_pool_hash:
            return

        del self.factory.chain.prev_txpool[0]
        self.factory.chain.prev_txpool.append(tx.txhash)

        for t in self.factory.chain.transaction_pool:  # duplicate tx already received, would mess up nonce..
            if tx.txhash == t.txhash:
                return

        self.factory.chain.update_pending_tx_pool(tx, self)

        self.factory.master_mr.register(tx.get_message_hash(), json_tx_obj, 'TX')
        self.broadcast(tx.get_message_hash(), 'TX')

        return


class P2PFactory(ServerFactory):
    def __init__(self, chain, nodeState, pos=None):
        self.master_mr = None
        self.pos = None
        self.protocol = P2PProtocol
        self.chain = chain
        self.nodeState = nodeState
        self.stake = c.enable_auto_staking  # default to mining off as the wallet functions are not that responsive at present with it enabled..
        self.peers_blockheight = {}
        self.target_retry = defaultdict(int)
        self.peers = []
        self.target_peers = {}
        self.fork_target_peers = {}
        self.connections = 0
        self.buffer = ''
        self.sync = 0
        self.partial_sync = [0, 0]
        self.long_gap_block = 0
        self.mining = 0
        self.newblock = 0
        self.exit = 0
        self.genesis = 0
        self.missed_block = 0
        self.requested = [0, 0]
        self.ip_geotag = 1  # to be disabled in main release as reveals IP..
        self.last_reveal_one = None
        self.last_reveal_two = None
        self.last_reveal_three = None

    # factory network functions
    def setPOS(self, pos):
        self.pos = pos
        self.master_mr = self.pos.master_mr

    def get_block_a_to_b(self, a, b):
        printL(('<<<Requested blocks:', a, 'to ', b, ' from peers..'))
        l = range(a, b)
        for peer in self.peers:
            if len(l) > 0:
                peer.transport.write(self.f_wrap_message('BN', str(l.pop(0))))
            else:
                return

    def get_block_n_random_peer(self, n):
        printL(('<<<Requested block: ', n, 'from random peer.'))
        random.choice(self.peers).get_block_n(n)
        return

    def get_block_n(self, n):
        printL(('<<<Requested block: ', n, 'from peers.'))
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('BN', str(n)))
        return

    def get_m_blockheight_from_random_peer(self):
        printL(('<<<Requested blockheight from random peer.'))
        random.choice(self.peers).get_m_blockheight_from_connection()
        return

    def get_blockheight_map_from_peers(self):
        printL(('<<<Requested blockheight_map from peers.'))
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('BM'))
        return

    def get_m_blockheight_from_peers(self):
        for peer in self.peers:
            peer.get_m_blockheight_from_connection()
        return

    def send_m_blockheight_to_peers(self):
        printL(('<<<Sending blockheight to peers.'))
        for peer in self.peers:
            peer.send_m_blockheight_to_peer()
        return

    def f_wrap_message(self, type, data=None):
        jdata = {}
        jdata['type'] = type
        if data:
            jdata['data'] = data
        str_data = json.dumps(jdata)
        return chr(255) + chr(0) + chr(0) + struct.pack('>L', len(str_data)) + chr(0) + str_data + chr(0) + chr(
            0) + chr(255)

    def send_st_to_peers(self, st):
        printL(('<<<Transmitting ST:', st.epoch))
        self.register_and_broadcast('ST', st.get_message_hash(), st.transaction_to_json())
        return

    def send_tx_to_peers(self, tx):
        printL(('<<<Transmitting TX: ', tx.txhash))
        self.register_and_broadcast('TX', tx.get_message_hash(), tx.transaction_to_json())
        return

    def send_reboot(self, json_hash):
        printL(('<<<Transmitting Reboot Command'))
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('reboot', json_hash))
        return

    # transmit reveal_one hash.. (node cast lottery vote)

    def send_stake_reveal_one(self, blocknumber=None):
        z = {}
        z['stake_address'] = self.chain.mining_address
        z['block_number'] = blocknumber
        if not z['block_number']:
            z['block_number'] = self.chain.block_chain_buffer.height() + 1  # next block..
        z['headerhash'] = self.chain.block_chain_buffer.get_strongest_headerhash(
            z['block_number'] - 1)  # demonstrate the hash from last block to prevent building upon invalid block..
        epoch = z['block_number'] // c.blocks_per_epoch
        hash_chain = self.chain.block_chain_buffer.hash_chain_get(z['block_number'])
        # +1 to skip first reveal
        z['reveal_one'] = hash_chain[-1][:-1][::-1][z['block_number'] - (epoch * c.blocks_per_epoch) + 1]
        z['vote_hash'] = None
        z['weighted_hash'] = None
        # epoch_PRF = self.chain.block_chain_buffer.get_epoch_PRF(blocknumber)
        epoch_seed = self.chain.block_chain_buffer.get_epoch_seed(blocknumber)
        # z['PRF'] = epoch_PRF[z['block_number'] - (epoch * c.blocks_per_epoch)]
        z['seed'] = epoch_seed
        z['SV_hash'] = self.chain.get_stake_validators_hash()

        _, hash = self.chain.select_hashchain(
            last_block_headerhash=self.chain.block_chain_buffer.get_strongest_headerhash(z['block_number'] - 1),
            stake_address=self.chain.mining_address, blocknumber=z['block_number'])

        for hashes in hash_chain:
            if hashes[-1] == hash:
                z['vote_hash'] = hashes[:-1][::-1][z['block_number'] - (epoch * c.blocks_per_epoch)]
                break

        if z['reveal_one'] == None or z['vote_hash'] == None:
            printL(('reveal_one or vote_hash None for stake_address: ', z['stake_address'], ' selected hash:', hash))
            printL(('reveal_one', z['reveal_one']))
            printL(('vote_hash', z['vote_hash']))
            printL(('hash', hash))
            return

        z['weighted_hash'] = self.chain.score(stake_address=z['stake_address'],
                                              reveal_one=z['reveal_one'],
                                              balance=self.chain.block_chain_buffer.get_st_balance(z['stake_address'], blocknumber),
                                              seed=epoch_seed)

        y = False
        tmp_stake_reveal_one = []
        for r in self.chain.stake_reveal_one:  # need to check the reveal list for existence already, if so..reuse..
            if r[0] == self.chain.mining_address:
                if r[1] == z['headerhash']:
                    if r[2] == z['block_number']:
                        if y == True:
                            continue  # if repetition then remove..
                        else:
                            z['reveal_one'] = r[3]
                            y = True
            tmp_stake_reveal_one.append(r)

        self.chain.stake_reveal_one = tmp_stake_reveal_one
        printL(('<<<Transmitting POS reveal_one ', blocknumber, self.chain.block_chain_buffer.get_st_balance(z['stake_address'], blocknumber)))

        self.last_reveal_one = z
        self.register_and_broadcast('R1', z['vote_hash'], helper.json_encode(z))
        #for peer in self.peers:
        #    peer.transport.write(self.f_wrap_message('R1', helper.json_encode(z)))
        #score = self.chain.score(stake_address=self.chain.mining_address,
        #                         reveal_one=z['reveal_one'],
        #                         balance=self.chain.block_chain_buffer.get_st_balance(self.chain.mining_address, blocknumber),
        #                         seed=epoch_seed)
        if y == False:
            self.chain.stake_reveal_one.append([z['stake_address'], z['headerhash'], z['block_number'], z['reveal_one'],
                                                z['weighted_hash'],  z['vote_hash']])  # don't forget to store our reveal in stake_reveal_one

        return z['reveal_one']  # , z['block_number']

    def send_last_stake_reveal_one(self):
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('R1', helper.json_encode(self.last_reveal_one)))

    def ip_geotag_peers(self):
        printL(('<<<IP geotag broadcast'))
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('IP'))
        return

    def ping_peers(self):
        printL(('<<<Transmitting network PING'))
        self.chain.last_ping = time.time()
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('PING'))
        return

    # send POS block to peers..

    def send_stake_block(self, block_obj):
        printL(('<<<Transmitting POS created block', str(block_obj.blockheader.blocknumber),
                block_obj.blockheader.headerhash))
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('S4', helper.json_bytestream(block_obj)))
        return

    # send/relay block to peers

    def send_block_to_peers(self, block, peer_identity=None):
        #printL(('<<<Transmitting block: ', block.blockheader.headerhash))
        self.register_and_broadcast('BK', block.blockheader.headerhash, helper.json_bytestream_bk(block))
        return

    def register_and_broadcast(self, msg_type, msg_hash, msg_json):
        self.master_mr.register(msg_hash, msg_json, msg_type)
        msg_hash = sha256(str(msg_hash))
        data = {'hash': msg_hash,
                'type': msg_type}

        for peer in self.peers:
            if msg_hash in self.master_mr.hash_peer:
                if peer in self.master_mr.hash_peer[msg_hash]:
                    continue
            peer.transport.write(self.f_wrap_message('MR', helper.json_encode(data)))

    # request transaction_pool from peers

    def get_tx_pool_from_peers(self):
        printL(('<<<Requesting TX pool from peers..'))
        for peer in self.peers:
            peer.transport.write(self.f_wrap_message('RT'))
        return

    # connection functions

    def connect_peers(self):
        printL(('<<<Reconnecting to peer list:'))
        for peer in self.chain.state.state_get_peers():
            reactor.connectTCP(peer, 9000, self)

    def clientConnectionLost(self, connector, reason):  # try and reconnect
        # printL(( 'connection lost: ', reason, 'trying reconnect'
        # connector.connect()
        return

    def clientConnectionFailed(self, connector, reason):
        # printL(( 'connection failed: ', reason
        return

    def startedConnecting(self, connector):
        # printL(( 'Started to connect.', connector
        return
