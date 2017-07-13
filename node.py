# QRL testnet node..
# -features POS, quantum secure signature scheme..

__author__ = 'pete'
import time, struct, random, copy, decimal
import chain, wallet, merkle
import configuration as c
import logger
from twisted.internet.protocol import ServerFactory, Protocol 
from twisted.internet import reactor, defer, task, threads
from merkle import sha256, numlist, hexseed_to_seed, mnemonic_to_seed, GEN_range, random_key
from traceback import extract_tb
from operator import itemgetter
from collections import Counter, defaultdict
from math import ceil
import statistics
import simplejson as json
import sys
import fork
import ntp

log, consensus = logger.getLogger(__name__)

cmd_list = ['balance', 'mining', 'seed', 'hexseed', 'recoverfromhexseed', 'recoverfromwords', 'stakenextepoch', 'stake', 'address', 'wallet', 'send', 'mempool', 'getnewaddress', 'quit', 'exit', 'search' ,'json_search', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight', 'json_block', 'reboot', 'peers']
api_list = ['block_data','stats', 'ip_geotag','exp_win','txhash', 'address', 'empty', 'last_tx', 'stake_reveal_ones', 'last_block', 'richlist', 'ping', 'stake_commits', 'stake_reveals', 'stake_list', 'stakers', 'next_stakers', 'latency']


#State Class
class state:
	def __init__(self):
		self.current = 'unsynced'
		self.epoch_diff = -1

	def update(self, state):
		self.current = state
		printL (( 'Status changed to ', self.current ))
		if self.current == 'synced':
			self.epoch_diff = 0
			global last_pos_cycle
			last_pos_cycle = time.time()
			self.update_epoch_diff(0)
			restart_post_block_logic()
		elif self.current == 'unsynced':
			global last_bk_time
			last_bk_time = time.time()
			restart_unsynced_logic()
		elif self.current == 'forked':
			stop_post_block_logic()
		elif self.current == 'syncing':
			global last_pb_time
			last_pb_time = time.time()
	def update_epoch_diff(self, value):
		self.epoch_diff = value

	def __repr__(self):
		return self.current

chain.state = state()

#Initializing function to log console output
printL = logger.PrintHelper(log, chain.state).printL
consensusL = logger.PrintHelper(consensus, chain.state).printL
chain.printL = printL
wallet.printL = printL
merkle.printL = printL
fork.printL = printL
ntp.printL = printL

r1_time_diff = defaultdict(list) #r1_time_diff[block_number] = { 'stake_address':{ 'r1_time_diff': value_in_ms }}
r2_time_diff = defaultdict(list) #r2_time_diff[block_number] = { 'stake_address':{ 'r2_time_diff': value_in_ms }}

incoming_blocks = {}
pending_blocks = {}	#Used only for synchronization of blocks
last_pos_cycle = 0
last_selected_height = 0
last_bk_time = 0
last_pb_time = 0
next_header_hash = None
next_block_number = None

def log_traceback(exctype, value, tb):				#Function to log error's traceback
	printL (( '*** Error ***' ))
	printL (( str(exctype) ))
	printL (( str(value) ))
	tb_info = extract_tb(tb)
	for line in tb_info:
		printL (( tb_info ))

#sys.excepthook = log_traceback

def parse(data):
		return data.replace('\r\n','')

def stop_monitor_bk():
	try: reactor.monitor_bk.cancel()
	except: pass

def restart_monitor_bk(delay=60):
	stop_monitor_bk()
	reactor.monitor_bk = reactor.callLater(delay, monitor_bk)

def monitor_bk():
	global last_pos_cycle, last_bk_time, last_pb_time
	
	if (chain.state.current == 'synced' or chain.state.current == 'unsynced') and time.time() - last_pos_cycle > 90:
		if chain.state.current == 'synced':
			stop_post_block_logic()
			reset_everything()
			chain.state.update('unsynced')
			chain.state.update_epoch_diff(-1)
		elif time.time() - last_bk_time > 120:
			last_pos_cycle = time.time()
			printL (( ' POS cycle activated by monitor_bk() ' ))
			chain.state.update('synced')

	if chain.state.current == 'syncing' and time.time() - last_pb_time > 60:
		stop_post_block_logic()
		reset_everything()
		chain.state.update('unsynced')
		chain.state.update_epoch_diff(-1)
	reactor.monitor_bk = reactor.callLater(60, monitor_bk)

def peers_blockheight_headerhash():
	for peer in f.peers:
		peer.fetch_headerhash_n(chain.m_blockheight())

def check_fork_status():
	current_height = chain.m_blockheight()
	block_hash_counter = Counter()
	for peer in f.peers:
		if current_height in peer.blocknumber_headerhash.keys():
			block_hash_counter[peer.blocknumber_headerhash[current_height]] += 1

	blockhash = block_hash_counter.most_common(1)
	if blockhash:
		blockhash = blockhash[0][0]
		actual_blockhash = chain.m_get_block(current_height).blockheader.headerhash
		if actual_blockhash != blockhash:
			printL (( 'Blockhash didnt matched in peers_blockheight()' ))
			printL (( 'Local blockhash - ', actual_blockhash ))
			printL (( 'Consensus blockhash - ', blockhash ))
			fork.fork_recovery(current_height, chain, randomize_headerhash_fetch)
			return True
	return
		
def peers_blockheight():
	if chain.state.current=='syncing':
		return
	if check_fork_status():
		return
	
	block_height_counter = Counter()
	
	for peer in f.peers:
		block_height_counter[peer.blockheight] += 1
	
	blocknumber = block_height_counter.most_common(1)
	if not blocknumber:
		return			#TODO : Re-Schedule with delay
	
	blocknumber = blocknumber[0][0]
	
	if blocknumber > chain.height(): #chain.m_blockheight():  len(chain.m_blockchain)
		pending_blocks['target'] = blocknumber
		printL (( 'Calling downloader from peers_blockheight due to no POS CYCLE ', blocknumber ))
		printL (( 'Download block from ', chain.height()+1 ,' to ', blocknumber ))
		global last_pb_time
		last_pb_time = time.time()
		chain.state.update('syncing')
		randomize_block_fetch(chain.height() + 1)
	return
	
def schedule_peers_blockheight(delay=100):
	try: reactor.peers_blockheight.cancel()
	except Exception: pass
	reactor.peers_blockheight = reactor.callLater(delay, peers_blockheight)
	try: reactor.peers_blockheight_headerhash.cancel()
	except Exception: pass
	reactor.peers_blockheight_headerhash = reactor.callLater(70, peers_blockheight_headerhash)

# pos functions. an asynchronous loop. 

# first block 1 is created with the stake list for epoch 0 decided from circulated st transactions

def pre_pos_1(data=None):		# triggered after genesis for block 1..
	printL(( 'pre_pos_1'))
	# are we a staker in the stake list?

	if chain.mining_address in chain.m_blockchain[0].stake_list:
		printL(('mining address:', chain.mining_address,' in the genesis.stake_list'))
		
		chain.my[0][1].hashchain(epoch=0)
		chain.hash_chain = chain.my[0][1].hc
		chain.block_chain_buffer.hash_chain[0] = chain.my[0][1].hc

		printL(('hashchain terminator: ', chain.my[0][1].hc_terminator))
		st = chain.StakeTransaction().create_stake_transaction(0, chain.my[0][1].hc_terminator)
		wallet.f_save_winfo()
		chain.add_st_to_pool(st)
		f.send_st_to_peers(st)			#send the stake tx to generate hashchain terminators for the staker addresses..
		printL(( 'await delayed call to build staker list from genesis'))
		reactor.callLater(5, pre_pos_2, st)
		return

	printL(( 'not in stake list..no further pre_pos_x calls'))
	return

def pre_pos_2(data=None):	
	printL(( 'pre_pos_2'))
	if chain.height() > 1:
		return
	# assign hash terminators to addresses and generate a temporary stake list ordered by st.hash..

	tmp_list = []

	for st in chain.stake_pool:
		if st.txfrom in chain.m_blockchain[0].stake_list:
			tmp_list.append([st.txfrom, st.hash, 0])
	
	chain.stake_list = sorted(tmp_list, key=itemgetter(1))	#required as doing chain.stake_list.index(s) which will result into different number on different servser

	printL(( 'genesis stakers ready = ', len(chain.stake_list),'/', chain.minimum_required_stakers ))
	printL(( 'node address:', chain.mining_address))

	if len(chain.stake_list) < chain.minimum_required_stakers:		# stake pool still not full..reloop..
		f.send_st_to_peers(data)
		printL(( 'waiting for stakers.. retry in 5s'))
		reactor.callID = reactor.callLater(5, pre_pos_2, data)
		return

	for s in chain.stake_list:
		if s[0] == chain.mining_address:
			spos = chain.stake_list.index(s)
	
	chain.epoch_prf = chain.pos_block_selector(chain.m_blockchain[-1].stake_seed, len(chain.stake_pool))	 #Use PRF to decide first block selector..
	chain.epoch_PRF = GEN_range(chain.m_blockchain[-1].stake_seed, 1, c.blocks_per_epoch, 32)
	chain.block_chain_buffer.epoch_PRF[0] = chain.epoch_PRF

	printL(( 'epoch_prf:', chain.epoch_prf[1]))
	printL(( 'spos:', spos))

	if spos == chain.epoch_prf[1]:
		printL(( 'designated to create block 1: building block..'))

		# create the genesis block 2 here..
		my_hash_chain, _ = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash, chain.mining_address, chain.my[0][1].hc, blocknumber=1)
		b = chain.m_create_block(my_hash_chain[-2])
		pre_block_logic(b)
	else:
		printL(( 'await block creation by stake validator:', chain.stake_list[chain.epoch_prf[1]][0]))
		last_bk_time = time.time()
		restart_unsynced_logic()
	return

def process_transactions(num):
	tmp_num = num
	for tx in chain.pending_tx_pool:
		tmp_num -= 1
		tx_peer = tx[1]
		tx = tx[0]
		if tx.validate_tx() != True:
			printL(( '>>>TX ', tx.txhash, 'failed validate_tx'))
			continue

		if tx.state_validate_tx() != True:
			printL(( '>>>TX', tx.txhash, 'failed state_validate'))
			continue

		printL(( '>>>TX - ', tx.txhash, ' from - ', tx_peer.transport.getPeer().host, ' relaying..'))
		chain.add_tx_to_pool(tx)

		txn_msg = tx_peer.wrap_message('TX',tx.transaction_to_json())
		for peer in tx_peer.factory.peers:
			if peer != tx_peer:
				peer.transport.write(txn_msg)
	
	for i in range(num-tmp_num):
		del chain.pending_tx_pool[0]
		del chain.pending_tx_pool_hash[0]

# create new block..

def create_new_block(winner, reveals, last_block_number):
	printL(( 'create_new_block'))
	tx_list = []
	for t in chain.transaction_pool:
		tx_list.append(t.txhash)
	block_obj = chain.create_stake_block(tx_list, winner, reveals, last_block_number)

	return block_obj

def reset_everything(data=None):
	printL(( '** resetting loops and emptying chain.stake_reveal_one, reveal_two, chain.pos_d and chain.expected_winner '))
	del chain.stake_reveal_one[:]
	return

def filter_reveal_one_two(blocknumber = None):
	if not blocknumber:
		blocknumber = chain.m_blockchain[-1].blockheader.blocknumber

	chain.stake_reveal_one = filter(lambda s: s[2] > blocknumber, chain.stake_reveal_one)
	
	return

def select_blockheight_by_consensus():
	#global last_selected_height
	global fmbh_allowed_peers
	block_height_counter = Counter()
	for identity in fmbh_allowed_peers:
		block_height_counter[s[2]] += 1
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

def restart_unsynced_logic(delay=0):
	try:  reactor.unsynced_logic.cancel()
	except:  pass
	reactor.unsynced_logic = reactor.callLater(delay, unsynced_logic)

def unsynced_logic():
	if chain.state.current == 'synced':
		return
	global fmbh_allowed_peers, fmbh_blockhash_peers
	fmbh_blockhash_peers = {}
	fmbh_allowed_peers = {}
	for peer in f.peers:
		fmbh_allowed_peers[peer.identity] = None
		peer.fetch_FMBH()
	reactor.unsynced_logic = reactor.callLater(20, start_download)

def start_download():
	#add peers and their identity to requested list
	#FMBH
	if chain.state.current == 'synced':
		return
	printL (( 'Checking Download..' ))
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
	#Adding all peers
	#TODO only trusted peer
	for peer in f.peers:
		f.target_peers[peer.identity] = peer
	chain.state.update('syncing')
	randomize_block_fetch(chain.height() + 1)
	
	
def pre_block_logic(block, peer_identity = None):
	global last_pos_cycle
	if len(chain.m_blockchain) == 0:
		chain.m_read_chain()

	blocknumber = block.blockheader.blocknumber
	headerhash = block.blockheader.headerhash
	prev_blockheaderhash = block.blockheader.prev_blockheaderhash
	curr_epoch = chain.height() / c.blocks_per_epoch
	next_epoch = (chain.height()+1) / c.blocks_per_epoch
	chain_buffer_height = chain.block_chain_buffer.height()
	#if blocknumber < chain.height() + 1 - chain.reorg_limit or blocknumber > chain.height() + 1:
	#if blocknumber < chain_buffer_height + 1 - chain.reorg_limit:
	if blocknumber <= chain.height():
		return False

	if chain.state.current == 'synced':
		if chain.block_chain_buffer.add_block(block):
			f.send_block_to_peers(block, peer_identity)
	else:
		if chain_buffer_height + 1 == blocknumber:
			if blocknumber>1 and chain.block_chain_buffer.add_block(block):
				f.send_block_to_peers(block, peer_identity)
			elif blocknumber == 1 and chain.block_chain_buffer.add_block_mainchain(block):
				f.send_block_to_peers(block, peer_identity)
			chain.state.update('synced')
		else:
			chain.block_chain_buffer.add_pending_block(block)

	if chain.state.current == 'synced':
		if chain_buffer_height + 1 == blocknumber:
			last_pos_cycle = time.time()
			restart_post_block_logic(15)
	#commented
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

#Calculate sum of blockreward for new_selector and old_selector
def sumBlockReward(old_selector, new_selector, blocknumber):
	sum_block_reward_old_sl = 0
	sum_block_reward_new_sl = 0
	for block in chain.m_blockchain[blocknumber:]:
		if block.blockheader.stake_selector == old_selector:
			sum_block_reward_old_sl += block.blockheader.block_reward
		elif block.blockheader.stake_selector == new_selector:
			sum_block_reward_new_sl += block.blockheader.block_reward

	return sum_block_reward_old_sl, sum_block_reward_new_sl

def update_nonce(block):
	sl = chain.stake_list_get()
	for s in sl:
		if block.blockheader.stake_selector == s[0]:
			s[2]-=1
	chain.stake_list_put(sl)

#Move txn from block to pending txn pool
#Function is used when a fork blocked is removed
def txn_block_to_pool(block):
	for tx in block.transactions:
		chain.add_tx_to_pool(tx)
		

def getBlockStakeInfo(block, block_reward = 0):
	total_stake = 0

	for reveal in block.blockheader.reveal_list:
		terminator = chain.reveal_to_terminator(reveal, block.blockheader.blocknumber)
		reveal_sv = chain.get_sv(terminator)
		if not reveal_sv:
			printL (( 'Block rejected : One of the reveal mismatched in reveal list' ))
			return
		total_stake += chain.state_balance(reveal_sv)

	score = chain.score(block.blockheader.stake_selector, block.blockheader.hash, block_reward, block.blockheader.blocknumber)

        return total_stake, score
	

def add_block(block):
	global last_pos_cycle
	if chainBuffer.add_block(block):
		printL (( 'Failed to add block' ))
		return
	
	if not chain.state_add_block(block):
		printL (( 'last block failed state/stake checks, removed from chain' ))
		return False
	last_pos_cycle = time.time()
	chain.m_blockchain.append(block)
	chain.remove_tx_in_block_from_pool(block) #modify fn to keep transaction in memory till reorg
	chain.remove_st_in_block_from_pool(block) #modify fn to keep transaction in memory till reorg
	chain.m_f_sync_chain()
	return True
		
def stop_post_block_logic(delay = 0):
	try: 
		reactor.post_block_logic.cancel()
		reactor.prepare_winners.cancel()
	except Exception: 
		pass
	

def restart_post_block_logic(delay = 0):
	stop_post_block_logic()
	reactor.post_block_logic = reactor.callLater(delay, post_block_logic)

# post block logic we initiate the next POS cycle, send R1, send ST, reset POS flags and remove unnecessary messages in chain.stake_reveal_one and _two..

def post_block_logic():
	filter_reveal_one_two()

	del chain.pos_flag[:]
	del chain.pos_d[:]
	del chain.expected_winner[:]

	our_reveal = None
	blocknumber = chain.block_chain_buffer.height() + 1

	if f.stake == True:
		if chain.mining_address in [s[0] for s in chain.block_chain_buffer.stake_list_get(blocknumber)]:
			our_reveal = f.send_stake_reveal_one(blocknumber)
			schedule_prepare_winners(our_reveal, blocknumber-1, 30)

		if chain.mining_address not in [s[0] for s in chain.block_chain_buffer.next_stake_list_get(blocknumber)]:
			st = chain.StakeTransaction().create_stake_transaction(blocknumber)
			f.send_st_to_peers(st)
			wallet.f_save_winfo()
			for t in chain.stake_pool:
				if st.hash == t.hash:
					return
			chain.add_st_to_pool(st)

	return

def schedule_prepare_winners(our_reveal, last_block_number, delay=0):
	try: reactor.prepare_winners.cancel()
	except: pass
	reactor.prepare_winners = reactor.callLater(delay, prepare_winners, our_reveal=our_reveal, last_block_number=last_block_number)

def prepare_winners(our_reveal, last_block_number):
	if not chain.state.current == 'synced':
		return
	filtered_reveal_one = []
	reveals = []
	next_block_num = last_block_number+1
	for s in chain.stake_reveal_one:
		if s[1] == chain.block_chain_buffer.get_strongest_headerhash(last_block_number) and s[2] == next_block_num:
			filtered_reveal_one.append(s)
			reveals.append(s[3])
			
	restart_post_block_logic(30)

	if len(filtered_reveal_one) <= 1:
		printL (( 'only received one reveal for this block.. blocknum #',next_block_num ))
		return

	epoch = (next_block_num)/c.blocks_per_epoch			#+1 = next block
	winners = chain.select_winners(filtered_reveal_one, topN=3)

	#reactor.process_blocks = reactor.callLater(30, process_blocks, winners=winners, our_reveal=our_reveal)

	if not(f.stake and our_reveal):
		return

	if our_reveal in winners:
		block = create_new_block(our_reveal, reveals, last_block_number)
		pre_block_logic(block)   # broadcast this block

	if len(chain.pending_tx_pool)>0 and len(chain.transaction_pool)<10:
		printL (( 'Processing TXNs if any' ))
		process_transactions(5)


def randomize_block_fetch(blocknumber):
	if chain.state.current!='syncing' or blocknumber<=chain.height():
		return

	if len(f.target_peers.keys()) == 0:
		printL (( ' No target peers found.. stopping download' ))
		return

	reactor.download_monitor = reactor.callLater(20, randomize_block_fetch, blocknumber)

	random_peer = f.target_peers[random.choice(f.target_peers.keys())]
	random_peer.fetch_block_n(blocknumber)

def randomize_headerhash_fetch(block_number):
	if chain.state.current != 'forked':
		return
	if block_number not in fork.pending_blocks or fork.pending_blocks[block_number][1]<=10: #retry only 11 times
		headerhash_monitor = reactor.callLater(15, randomize_headerhash_fetch, block_number)
		if len(f.peers) > 0:
			try:
				if len(f.fork_target_peers) == 0:
					for peer in f.peers:
						f.fork_target_peers[peer.identity] = peer
				if len(f.fork_target_peers) > 0:
					random_peer = f.fork_target_peers[random.choice(f.fork_target_peers.keys())]
					count = 0
					if block_number in fork.pending_blocks:
						count = fork.pending_blocks[block_number][1]+1
					fork.pending_blocks[block_number] = [random_peer.identity, count, None, headerhash_monitor]
					random_peer.fetch_headerhash_n(block_number)
			except:
				printL (( 'Exception at randomize_headerhash_fetch' ))
		else:
			printL (( 'No peers connected.. Will try again... randomize_headerhash_fetch: ', block_number ))
	else:
		chain.state.update('unsynced')


# blockheight map for connected nodes - when the blockheight seems up to date after a sync or error, we check all connected nodes to ensure all on same chain/height..
# note - may not return correctly during a block propagation..
# once working alter to identify fork better..

def blockheight_map():

	#i = [block_number, headerhash, self.transport.getPeer().host]

	printL(( 'blockheight_map:'))
	printL(( chain.blockheight_map))

	# first strip out any laggards..
	chain.blockheight_map = filter(lambda s: s[0]>=chain.m_blockheight(), chain.blockheight_map)

	bmap_fail = 0

	# next identify any node entries which are not exactly correct..

	for s in chain.blockheight_map:
		if s[0]==chain.m_blockheight() and s[1]==chain.m_blockchain[-1].blockheader.headerhash:
			printL(( 'node: ', s[2], '@', s[0], 'w/:', s[1], 'OK'))
		elif s[0] > chain.m_blockheight():
			printL(( 'warning..', s[2], 'at blockheight', s[0]))
			bmap_fail = 1

	# wipe it..

	del chain.blockheight_map[:]

	if bmap_fail == 1:
		return False

	return True

# factories and protocols..

class ApiProtocol(Protocol):

	def __init__(self):
		pass

	def parse_cmd(self, data):

		data = data.split()			#typical request will be: "GET /api/{command}/{parameter} HTTP/1.1"
		
		#printL(( data
		
		if len(data) == 0: return

		if data[0] != 'GET' and data[0] != 'OPTIONS':
			return False

		if data[0] == 'OPTIONS':
			http_header_OPTIONS = ("HTTP/1.1 200 OK\r\n"
								   "Access-Control-Allow-Origin: *\r\n"
								   "Access-Control-Allow-Methods: GET\r\n"
								   "Access-Control-Allow-Headers: x-prototype-version,x-requested-with\r\n"
								   "Content-Length: 0\r\n"
								   "Access-Control-Max-Age: 2520\r\n"
								   "\r\n")
			self.transport.write(http_header_OPTIONS)
			return 

		data = data[1][1:].split('/')

		if data[0].lower() != 'api':
			return False

		if len(data) == 1:
			data.append('')

		if data[1] == '':
			data[1] = 'empty'

		if data[1].lower() not in api_list:			#supported {command} in api_list
			error = {'status': 'error', 'error': 'supported method not supplied', 'parameter' : data[1] }
			self.transport.write(chain.json_print_telnet(error))
			return False
		
		my_cls = ApiProtocol()					#call the command from api_list directly
		api_call = getattr(my_cls, data[1].lower())	
		
		if len(data) < 3:
			json_txt = api_call()
			#self.transport.write(api_call())
		else:
			json_txt = api_call(data[2])
			#self.transport.write(api_call(data[2]))

		http_header_GET = ("HTTP/1.1 200 OK\r\n"
						   "Content-Type: application/json\r\n"
						   "Content-Length: %s\r\n"
						   "Access-Control-Allow-Headers: x-prototype-version,x-requested-with\r\n"
						   "Access-Control-Max-Age: 2520\r\n"
						   "Access-Control-Allow-Origin: *\r\n"
						   "Access-Control-Allow-Methods: GET\r\n"
						   "\r\n") % (str(len(json_txt)))

		self.transport.write(http_header_GET+json_txt)
		return

	def exp_win(self, data=None):
		printL(( '<<< API expected winner call'))
		return chain.exp_win(data)

	def ping(self, data=None):
		printL(( '<<< API network latency ping call'))
		f.ping_peers()									 # triggers ping for all connected peers at timestamp now. after pong response list is collated. previous list is delivered.
		pings = {}
		pings['status'] = 'ok'
		pings['peers'] = {}
		pings['peers'] = chain.ping_list
		return chain.json_print_telnet(pings)

	def stakers(self, data=None):
		printL(( '<<< API stakers call'))
		return chain.stakers(data)

	def next_stakers(self, data=None):
		printL(( '<<< API next_stakers call'))
		return chain.next_stakers(data)

	def stake_commits(self, data=None):
		printL(( '<<< API stake_commits call'))
		return chain.stake_commits(data)

	def stake_reveals(self, data=None):
		printL(( '<<< API stake_reveals call'))
		return chain.stake_reveals(data)

	def stake_reveal_ones(self, data=None):
		printL(( '<<< API stake_reveal_ones'))
		return chain.stake_reveal_ones(data)

	def richlist(self, data=None):
		printL(( '<<< API richlist call'))
		return chain.richlist(data)

	def last_block(self, data=None):
		printL(( '<<< API last_block call'))
		return chain.last_block(data)

	def last_tx(self, data=None):
		printL(( '<<< API last_tx call'))
		return chain.last_tx(data)

	def ip_geotag(self, data=None):
		printL(( '<<< API ip_geotag call'))
		f.ip_geotag_peers()
		return chain.ip_geotag(data)

	def empty(self, data=None):
		error = {'status': 'error','error' : 'no method supplied', 'methods available' : 'block_data, stats, txhash, address, last_tx, last_block, richlist, ping, stake_commits, stake_reveals, stakers, next_stakers'}
		return chain.json_print_telnet(error)

	def block_data(self, data=None):				# if no data = last block ([-1])			#change this to add error.. 
		error = {'status': 'error', 'error' : 'block not found', 'method': 'block_data', 'parameter' : data}
		printL(( '<<< API block data call', data	))
		if not data:
			#return chain.json_printL((_telnet(chain.m_get_last_block())
			data = chain.m_get_last_block()
			data1 = copy.deepcopy(data)
			data1.status = 'ok'
			return chain.json_print_telnet(data1)
		try: int(data)														# is the data actually a number?
		except: 
			return chain.json_print_telnet(error)
		#js_bk = chain.json_printL((_telnet(chain.m_get_block(int(data)))
		js_bk = chain.m_get_block(int(data))
		#if js_bk == 'false':
		if js_bk == False:
			return chain.json_print_telnet(error)
		else:
			js_bk1 = copy.deepcopy(js_bk)
			js_bk1.status = 'ok'
			js_bk1.blockheader.block_reward = js_bk1.blockheader.block_reward/100000000.000000000
			return chain.json_print_telnet(js_bk1)

	def stats(self, data=None):
		printL(( '<<< API stats call'))

		# calculate staked/emission %
		b=0
		for s in chain.stake_list_get():
			b+=chain.state_balance(s[0])
		staked = decimal.Decimal((b/100000000.000000000)/(chain.db.total_coin_supply()/100000000.000000000)*100).quantize(decimal.Decimal('1.00')) #/100000000.000000000)
		staked = float(str(staked))
		# calculate average blocktime over last 100 blocks..

		z=0
		t = []

		for b in reversed(chain.m_blockchain[-100:]):
			if b.blockheader.blocknumber > 0:
				x = b.blockheader.timestamp-chain.m_blockchain[b.blockheader.blocknumber-1].blockheader.timestamp
				t.append(x)
				z+=x

		#printL(( 'mean', z/len(chain.m_blockchain[-100:]), 'max', max(t), 'min', min(t), 'variance', max(t)-min(t)

		net_stats = {'status': 'ok', 'version': chain.version_number, 'block_reward' : chain.m_blockchain[-1].blockheader.block_reward/100000000.00000000, 'stake_validators' : len(chain.m_blockchain[-1].blockheader.reveal_list), 'epoch' : chain.m_blockchain[-1].blockheader.epoch, 'staked_percentage_emission' : staked , 'network' : 'qrl testnet', 'network_uptime': time.time()-chain.m_blockchain[1].blockheader.timestamp,'block_time' : z/len(chain.m_blockchain[-100:]), 'block_time_variance' : max(t)-min(t) ,'blockheight' : chain.m_blockheight(), 'nodes' : len(f.peers)+1, 'emission': chain.db.total_coin_supply()/100000000.000000000, 'unmined' : 21000000-chain.db.total_coin_supply()/100000000.000000000 }
		return chain.json_print_telnet(net_stats)

	def txhash(self, data=None):
		printL(( '<<< API tx/hash call', data))
		return chain.search_txhash(data)

	def address(self, data=None):
		printL(( '<<< API address call', data))
		return chain.search_address(data)

	def dataReceived(self, data=None):
		self.parse_cmd(data)
		self.transport.loseConnection()
	
	def connectionMade(self):
		self.factory.connections += 1
		#printL(( '>>> new API connection'

	def connectionLost(self, reason):
		#printL(( '<<< API disconnected'
		self.factory.connections -= 1

	def latency(self, type=None):
		output = {}
		if type and type.lower() in ['mean', 'median', 'last']:
			for block_num in chain.stake_validator_latency.keys():
				output[block_num] = {}
				for stake in chain.stake_validator_latency[block_num].keys():
					time_list = chain.stake_validator_latency[block_num][stake]
					print time_list
					output[block_num][stake] = {}
					if type.lower()=='mean':
						output[block_num][stake]['r1_time_diff'] =  statistics.mean(time_list['r1_time_diff'])
						if 'r2_time_diff' in time_list:
							output[block_num][stake]['r2_time_diff'] =  statistics.mean(time_list['r2_time_diff'])
					elif type.lower()=='last':
						output[block_num][stake]['r1_time_diff'] = time_list['r1_time_diff'][-1]
						if 'r2_time_diff' in time_list:
							output[block_num][stake]['r2_time_diff'] = time_list['r2_time_diff'][-1]
					elif type.lower()=='median':
						output[block_num][stake]['r1_time_diff'] = statistics.median(time_list['r1_time_diff'])
						if 'r2_time_diff' in time_list:
							output[block_num][stake]['r2_time_diff'] = statistics.median(time_list['r2_time_diff'])
		else:
			output = chain.stake_validator_latency
		output = json.dumps(output)
		return output

class WalletProtocol(Protocol):

	def __init__(self):		
		pass

	def parse_cmd(self, data):
	
		data = data.split()
		args = data[1:]

		if len(data) != 0:
		 if data[0] in cmd_list:			

			if data[0] == 'getnewaddress':
				self.getnewaddress(args)
				return

			if data[0] == 'hexseed':
				for c in chain.my:
					if type(c[1])== list:
						pass
					else:
						if c[1].type == 'XMSS':
							self.transport.write('Address: '+ c[1].address+'\r\n')
							self.transport.write('Recovery seed: '+c[1].hexSEED+'\r\n')
				return

			if data[0] == 'seed':
				for c in chain.my:
					if type(c[1])== list:
						pass
					else:
						if c[1].type == 'XMSS':
							self.transport.write('Address: '+ c[1].address+'\r\n')
							self.transport.write('Recovery seed: '+c[1].mnemonic+'\r\n')
				return

			elif data[0] == 'search':
				if not args:
					self.transport.write('>>> Usage: search <txhash or Q-address>'+'\r\n')
					return
				for result in chain.search_telnet(args[0], long=0):
					self.transport.write(result+'\r\n')
				return

			elif data[0] == 'json_search':
				if not args:
					self.transport.write('>>>Usage: search <txhash or Q-address>'+'\r\n')
					return
				for result in chain.search_telnet(args[0], long=1):
					self.transport.write(result+'\r\n')
				return

			elif data[0] == 'json_block':
				
				if not args:
					#chain.json_printL(((chain.m_get_last_block())
					self.transport.write(chain.json_print_telnet(chain.m_get_last_block())+'\r\n')
					return
				try: int(args[0])
				except:	
						self.transport.write('>>> Try "json_block <block number>" '+'\r\n') 
						return

				if int(args[0]) > chain.m_blockheight():
					self.transport.write('>>> Block > Blockheight'+'\r\n')
					return

				self.transport.write(chain.json_print_telnet(chain.m_get_block(int(args[0])))+'\r\n')
				return

			elif data[0] == 'savenewaddress':
				self.savenewaddress()
			
			elif data[0] == 'recoverfromhexseed':
				if not args or not hexseed_to_seed(args[0]):
					self.transport.write('>>> Usage: recoverfromhexseed <paste in hexseed>'+'\r\n')
					self.transport.write('>>> Could take up to a minute..'+'\r\n')
					self.transport.write('>>> savenewaddress if Qaddress matches expectations..'+'\r\n')
					return

				self.transport.write('>>> trying.. this could take up to a minute..'+'\r\n')
				addr = wallet.getnewaddress(type='XMSS', SEED=hexseed_to_seed(args[0]))
				self.factory.newaddress = addr
				self.transport.write('>>> Recovery address: '+ addr[1].address +'\r\n')
				self.transport.write('>>> Recovery seed phrase: '+addr[1].mnemonic + '\r\n')
				self.transport.write('>>> hexSEED confirm: '+addr[1].hexSEED+'\r\n')
				self.transport.write('>>> savenewaddress if Qaddress matches expectations..'+'\r\n')
				return

			elif data[0] == 'recoverfromwords':
				if not args:
					self.transport.write('>>> Usage: recoverfromwords <paste in 32 mnemonic words>'+'\r\n')
					return
				self.transport.write('>>> trying..this could take up to a minute..'+'\r\n')
				if len(args) != 32:
					self.transport.write('>>> Usage: recoverfromwords <paste in 32 mnemonic words>'+'\r\n')
					return
				args = ' '.join(args)
				addr = wallet.getnewaddress(type='XMSS', SEED=mnemonic_to_seed(args))
				self.factory.newaddress = addr
				self.transport.write('>>> Recovery address: '+ addr[1].address +'\r\n')
				self.transport.write('>>> Recovery hexSEED: '+addr[1].hexSEED + '\r\n')
				self.transport.write('>>> Mnemonic confirm: '+addr[1].mnemonic+'\r\n')
				self.transport.write('>>> savenewaddress if Qaddress matches expectations..'+'\r\n')
				return

			elif data[0] == 'stake':
				self.transport.write('>> Toggling stake from: '+str(f.stake)+' to: '+str(not f.stake)+'\r\n')
				f.stake = not f.stake
				printL(( 'STAKING set to: ', f.stake))
				return

			elif data[0] == 'stakenextepoch':
				self.transport.write('>>> Sending a stake transaction for address: '+chain.mining_address+' to activate next epoch('+str(c.blocks_per_epoch-(chain.m_blockchain[-1].blockheader.blocknumber-(chain.m_blockchain[-1].blockheader.epoch*c.blocks_per_epoch)))+' blocks time)'+'\r\n')
				printL(( 'STAKE for address:', chain.mining_address))
				f.send_st_to_peers(chain.StakeTransaction().create_stake_transaction(chain.block_chain_buffer.height()+1))
				return
			
			elif data[0] == 'send':
				self.send_tx(args)

			elif data[0] == 'mempool':
				self.transport.write('>>> Number of transactions in memory pool: '+ str(len(chain.transaction_pool))+'\r\n')

			elif data[0] == 'help':
				self.transport.write('>>> QRL ledger help: try quit, wallet, send, getnewaddress, search, recoverfromhexseed, recoverfromwords, stake, stakenextepoch, mempool, json_block, json_search, seed, hexseed, getinfo, peers, or blockheight'+'\r\n')
				#removed 'hrs, hrs_check,'
			elif data[0] == 'quit' or data[0] == 'exit':
				self.transport.loseConnection()

			#elif data[0] == 'balance':
			#	self.state_balance(args)

			elif data[0] == 'listaddresses':
					addresses, num_sigs, types = wallet.inspect_wallet()
					
					for x in range(len(addresses)):
						self.transport.write(str(x)+', '+addresses[x]+'\r\n')

			elif data[0] == 'wallet':
					self.wallet()
					
			elif data[0] == 'getinfo':
					self.transport.write('>>> Version: '+chain.version_number+'\r\n')
					self.transport.write('>>> Uptime: '+str(time.time()-start_time)+'\r\n')
					self.transport.write('>>> Nodes connected: '+str(len(f.peers))+'\r\n')
					self.transport.write('>>> Staking set to: '+ str(f.stake)+'\r\n')
					self.transport.write('>>> Sync status: '+chain.state.current+'\r\n')

			elif data[0] == 'blockheight':
					self.transport.write('>>> Blockheight: '+str(chain.m_blockheight())+'\r\n')
					self.transport.write('>>> Headerhash: '+chain.m_blockchain[-1].blockheader.headerhash+'\r\n')

			elif data[0] == 'peers':
					self.transport.write('>>> Connected Peers:\r\n')
					for peer in f.peers:
						self.transport.write('>>> ' + peer.identity + " [" + peer.version + "]  blockheight: " + str(peer.blockheight) + '\r\n')

			elif data[0] == 'reboot':
				if len(args)<1:
					self.transport.write('>>> reboot <password>\r\n')
					self.transport.write('>>> or\r\n')
					self.transport.write('>>> reboot <password> <nonce>\r\n')
					return 
				json_hash, err = None, None
				if len(args)==2:
					json_hash, status = chain.generate_reboot_hash(args[0], args[1])
				else:
					json_hash, status = chain.generate_reboot_hash(args[0])
				if json_hash:
					f.send_reboot(json_hash)
					chain.state.update('synced')
				self.transport.write(status)
		else:
			return False

		return True

	def dataReceived(self, data):
		self.factory.recn += 1
		if self.parse_cmd(parse(data)) == False:
			self.transport.write(">>> Command not recognised. Use 'help' for details"+'\r\n')
	
	def connectionMade(self):
		self.transport.write(self.factory.stuff)
		self.factory.connections += 1
		if self.factory.connections > 1:
			printL(( 'only one local connection allowed'))
			self.transport.write('only one local connection allowed, sorry')
			self.transport.loseConnection()
		else:
			if self.transport.getPeer().host == '127.0.0.1':
				printL(( '>>> new local connection', str(self.factory.connections), self.transport.getPeer()))
				# welcome functions to run here..
			else:
				self.transport.loseConnection()
				printL(( 'Unauthorised remote login attempt..'))

	def connectionLost(self, reason):
		self.factory.connections -= 1

	# local wallet access functions..

	def getbalance(self, addr):
		if chain.state_uptodate() is False:
			self.transport.write('>>> LevelDB not up to date..'+'\r\n')
			return
		if not addr: 
			self.transport.write('>>> Usage: getbalance <address> (Addresses begin with Q)'+'\r\n')
			return
		if addr[0][0] != 'Q':
			self.transport.write('>>> Usage: getbalance <address> (Addresses begin with Q)'+'\r\n')
			return
		if chain.state_address_used(addr[0]) is False:
			self.transport.write('>>> Unused address.'+'\r\n')
			return
		self.transport.write('>>> balance:  '+str(chain.state_balance(addr[0]))+'\r\n')
		return

	def getnewaddress(self, args):
		if not args or len(args) > 2:
			self.transport.write('>>> Usage: getnewaddress <n> <type (XMSS, WOTS or LDOTS)>'+'\r\n')
			self.transport.write('>>> i.e. getnewaddress 4096 XMSS'+'\r\n')
			self.transport.write('>>> or: getnewaddress 128 LDOTS'+'\r\n')
			self.transport.write('>>> (new address creation can take a while, please be patient..)'+'\r\n')
			return 
		else:
			try:	int(args[0])
			except:
					self.transport.write('>>> Invalid number of signatures. Usage: getnewaddress <n signatures> <type (XMSS, WOTS or LDOTS)>'+'\r\n')
					self.transport.write('>>> i.e. getnewaddress 4096 XMSS'+'\r\n')
					return

		#SHORTEN WITH args[1].upper() 

		if args[1] != 'XMSS' and args[1] != 'xmss' and args[1] != 'WOTS' and args[1] != 'wots' and args[1] != 'LDOTS' and args[1] != 'ldots' and args[1] != 'LD':
			self.transport.write('>>> Invalid signature address type. Usage: getnewaddress <n> <type (XMSS, WOTS or LDOTS)>'+'\r\n')
			self.transport.write('>>> i.e. getnewaddress 4096 XMSS'+'\r\n')
			return

		if args[1] == 'xmss':
			args[1] = 'XMSS'

		if args[1] == 'wots':
			args[1] = 'WOTS'

		if args[1] == 'ldots' or args[1] == 'LD':
			args[1] = 'LDOTS'

		if int(args[0]) > 256 and args[1] != 'XMSS':
			self.transport.write('>>> Try a lower number of signatures or you may be waiting a very long time...'+'\r\n')
			return

		self.transport.write('>>> Creating address..please wait'+'\r\n')
		addr = wallet.getnewaddress(int(args[0]), args[1])

		if type(addr[1]) == list:
			self.transport.write('>>> Keypair type: '+''.join(addr[1][0].type+'\r\n'))
			self.transport.write('>>> Signatures possible with address: '+str(len(addr[1]))+'\r\n')
			self.transport.write('>>> Address: '+''.join(addr[0])+'\r\n')

		else:	#xmss
			self.transport.write('>>> Keypair type: '+''.join(addr[1].type+'\r\n'))
			self.transport.write('>>> Signatures possible with address: '+str(addr[1].signatures)+'\r\n')
			self.transport.write('>>> Address: '+addr[1].address+'\r\n')

		self.transport.write(">>> type 'savenewaddress' to append to wallet file"+'\r\n')
		self.factory.newaddress = addr
		return

	def savenewaddress(self):
		if not self.factory.newaddress:
			self.transport.write(">>> No new addresses created, yet. Try 'getnewaddress'"+'\r\n')
			return
		wallet.f_append_wallet(self.factory.newaddress)
		self.transport.write('>>> new address saved in wallet.'+'\r\n')
		return

	def send_tx(self, args):
		if not args or len(args) < 3:
			self.transport.write('>>> Usage: send <from> <to> <amount>'+'\r\n')
			self.transport.write('>>> i.e. send 0 4 100'+'\r\n')
			self.transport.write('>>> ^ will send 100 coins from address 0 to 4 from the wallet'+'\r\n')
			self.transport.write('>>> <to> can be a pasted address (starts with Q)'+'\r\n')
			return

		try: int(args[0])
		except: 
				self.transport.write('>>> Invalid sending address. Try a valid number from your wallet - type wallet for details.'+'\r\n')
				return
		
		if int(args[0]) > len(wallet.list_addresses())-1:
				self.transport.write('>>> Invalid sending address. Try a valid number from your wallet - type wallet for details.'+'\r\n')
				return

		if len(args[1]) > 1 and args[1][0] != 'Q' and chain.state_hrs(args[1]) != False:
			pass
		elif args[1][0] == 'Q':
			pass
		else:
			try: int(args[1])
			except:
					self.transport.write('>>> Invalid receiving address - addresses must start with Q. Try a number from your wallet.'+'\r\n')
					return
			if int(args[1]) > len(wallet.list_addresses())-1:
					self.transport.write('>>> Invalid receiving address - addresses must start with Q. Try a number from your wallet.'+'\r\n')
					return	
			args[1] = int(args[1])
		
		balance = chain.state_balance(chain.my[int(args[0])][0])

		try: float(args[2])
		except: 
				self.transport.write('>>> Invalid amount type. Type a number (less than or equal to the balance of the sending address)'+'\r\n')
				return



		#to_send = decimal.Decimal(format(decimal.Decimal(args[2]), '.8f')*100000000)
		amount = decimal.Decimal(decimal.Decimal(args[2])*100000000).quantize(decimal.Decimal('1'), rounding= decimal.ROUND_HALF_UP)


		if balance < amount:
				self.transport.write('>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
				return

		tx = chain.create_my_tx(txfrom=int(args[0]), txto=args[1], amount=amount)
		
		#self.transport.write(msg+'\r\n')
		if tx is False:
			return
		
		#printL(( 'new local tx: ', tx
		if tx.validate_tx():
			if not tx.state_validate_tx():
				self.transport.write('>>> OTS key reused')
				return
		else:
			self.transport.write('>>> TXN failed at validate_tx')
			printL(( '>>> TXN failed at validate_tx' ))
			return

		f.send_tx_to_peers(tx)
		self.transport.write('>>> '+str(tx.txhash))
		self.transport.write('>>> From: '+str(tx.txfrom)+' To: '+str(tx.txto)+' For: '+str(tx.amount/100000000.000000000)+'\r\n'+'>>>created and sent into p2p network'+'\r\n')
		return

	def wallet(self):
		if chain.state_uptodate() == False:
			chain.state_read_chain()
		self.transport.write('>>> Wallet contents:'+'\r\n')
		y=0
		for address in wallet.list_addresses():
			self.transport.write(str(y)+str(address)+'\r\n')
			y+=1

class p2pProtocol(Protocol):

	def __init__(self):		
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
		try:
			if 'data' in jdata:
				getattr(self, func)(jdata['data'])
			else:
				getattr(self, func)()
		except KeyboardInterrupt:
			printL (( "parse_msg Exception while calling " ))
			printL (( "Func name ", func ))
			#printL (( "JSON data ", jdata ))
			pass

	def reboot(self, data):
		hash_dict = json.loads(data)
		if not ('hash' in hash_dict and 'nonce' in hash_dict):
			return
		if not chain.validate_reboot(hash_dict['hash'], hash_dict['nonce']):
			return
		for peer in self.factory.peers:
			if peer!=self:
				peer.transport.write(self.wrap_message('reboot',data))
		printL (( 'Initiating Reboot Sequence.....' ))
		
		chain.state.update('synced')

	def TX(self, data):				#tx received..
		self.recv_tx(data)
		return
		
	def ST(self, data):
		try: st = chain.StakeTransaction().json_to_transaction(data)
		except: 
			printL(( 'st rejected - unable to decode serialised data - closing connection'))
			self.transport.loseConnection()
			return

		for t in chain.stake_pool:			#duplicate tx already received, would mess up nonce..
			if st.hash == t.hash:
				return
			
		if st.validate_tx() and st.state_validate_tx():
			chain.add_st_to_pool(st)
		else:
			printL(( '>>>ST',st.hash, 'invalid state validation failed..')) #' invalid - closing connection to ', self.transport.getPeer().host
			return

		#printL(( '>>>ST - ', st.hash, ' from - ', self.transport.getPeer().host, ' relaying..'))
			
		for peer in self.factory.peers:
			if peer != self:
				peer.transport.write(self.wrap_message('ST',st.transaction_to_json()))
		return


	def BM(self, data=None):	# blockheight map for synchronisation and error correction prior to POS cycle resync..
		if not data:
			printL(( '<<<Sending block_map', self.transport.getPeer().host))
			z = {}
			z['block_number'] = chain.m_blockchain[-1].blockheader.blocknumber
			z['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash
			self.transport.write(self.wrap_message('BM',chain.json_encode(z)))
			return
		else:
			printL(( '>>>Receiving block_map'))
			z = chain.json_decode(data)
			block_number = z['block_number']
			headerhash = z['headerhash'].encode('latin1')

			i = [block_number, headerhash, self.transport.getPeer().host]
			printL(( i))
			if i not in chain.blockheight_map:
				chain.blockheight_map.append(i)
			return	

	def BK(self, data):			#block received
		printL (( '<<< Received block from ', self.identity ))
		try:	block = chain.json_decode_block(data)
		except:
			printL(( 'block rejected - unable to decode serialised data', self.transport.getPeer().host))
			return
		pre_block_logic(block, self.identity)
		return

	def isNoMoreBlock(self, data):
		if type(data) == int:
			blocknumber = data
			if blocknumber != self.last_requested_blocknum:
				return True
			try: reactor.download_monitor.cancel()
			except: pass
			chain.state.update('synced')
			return True
		return False

	def PBB(self, data):
		global last_pb_time
		last_pb_time = time.time()
		try:
			if self.isNoMoreBlock(data):
				return

			data = chain.json_decode(data)
			blocknumber = int(data.keys()[0].encode('ascii'))

			if blocknumber != self.last_requested_blocknum:
				printL (( 'Blocknumber not found in pending_blocks', blocknumber, self.identity ))
				return
			
			for jsonBlock in data[unicode(blocknumber)]:
				block = chain.json_decode_block(json.dumps(jsonBlock))
				printL (( '>>>Received Block #', block.blockheader.blocknumber))

				status = chain.block_chain_buffer.add_block(block)
				if type(status)==bool and not status:
					printL (( "[PBB] Failed to add block by add_block, re-requesting the block #",blocknumber ))
					printL (( 'Skipping one block' ))
					continue

			try: reactor.download_block.cancel()
			except Exception: pass

			#Below code is to stop downloading, once we see that we reached to blocknumber that are in pending_blocks
			#This could be exploited by sybil node, to send blocks in pending_blocks in order to disrupt downloading
			#TODO: required a better fix
			if len(chain.block_chain_buffer.pending_blocks)>0 and min(chain.block_chain_buffer.pending_blocks.keys())==blocknumber:
				chain.block_chain_buffer.process_pending_blocks()
				return
			randomize_block_fetch(blocknumber+1)
		except KeyboardInterrupt:
			printL(( '.block rejected - unable to decode serialised data', self.transport.getPeer().host))
			return


	def PB(self, data):
		global last_pb_time
		last_pb_time = time.time()
		try:
			if self.isNoMoreBlock(data):
				return

			block = chain.json_decode_block(data)
			blocknumber = block.blockheader.blocknumber
			printL (( '>>>Received Block #', blocknumber))
			if blocknumber != self.last_requested_blocknum:
				printL (( 'Didnt match', pending_blocks[block.blockheader.blocknumber][0], thisPeerHost.host, thisPeerHost.port ))
				return

			if blocknumber > chain.height() and not chain.block_chain_buffer.add_block_mainchain(block):
				return

			try: reactor.download_monitor.cancel()
			except Exception: pass

			randomize_block_fetch(blocknumber+1)

		except KeyboardInterrupt:
			printL(( '.block rejected - unable to decode serialised data', self.transport.getPeer().host))
		return

	def PH(self, data):
		if chain.state.current == 'forked':
			fork.verify(data, self.identity, chain, randomize_headerhash_fetch)
		else:
			mini_block = json.loads(data)
			self.blocknumber_headerhash[mini_block['blocknumber']] = mini_block['headerhash']

	def LB(self):			#request for last block to be sent
		printL(( '<<<Sending last block', str(chain.m_blockheight()), str(len(chain.json_bytestream(chain.m_get_last_block()))),' bytes', 'to node: ', self.transport.getPeer().host))
		self.transport.write(self.wrap_message('BK',chain.json_bytestream_bk(chain.m_get_last_block())))
		return

	def FMBH(self):	#Fetch Maximum Blockheight and Headerhash
		printL(( '<<<Sending blockheight and headerhash to: ', self.transport.getPeer().host, str(time.time())))
		data = {}
		data['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash
		data['blocknumber'] = chain.m_blockchain[-1].blockheader.blocknumber
		self.transport.write(self.wrap_message('PMBH',chain.json_encode(data)))


	def PMBH(self, data): #Push Maximum Blockheight and Headerhash
		data = chain.json_decode(data)
		if not data or 'headerhash' not in data or 'blocknumber' not in data:
			return
		global fmbh_allowed_peers
		global fmbh_blockhash_peers
		if self.identity in fmbh_allowed_peers:
			fmbh_allowed_peers[self.identity] = data
			if data['headerhash'] not in fmbh_blockhash_peers:
				fmbh_blockhash_peers[data['headerhash']] = {'blocknumber':data['blocknumber'], 'peers': []}
			fmbh_blockhash_peers[data['headerhash']]['peers'].append(self)

	def MB(self):		#we send with just prefix as request..with CB number and blockhash as answer..
		printL(( '<<<Sending blockheight to:', self.transport.getPeer().host, str(time.time()) ))
		self.send_m_blockheight_to_peer()
		return
			
	def CB(self, data):
		z = chain.json_decode(data)
		block_number = z['block_number']
		headerhash = z['headerhash'].encode('latin1')
				
		self.blockheight = block_number
				
		printL(( '>>>Blockheight from:', self.transport.getPeer().host, 'blockheight: ', block_number, 'local blockheight: ', str(chain.m_blockheight()), str(time.time())))

		self.factory.peers_blockheight[self.transport.getPeer().host + ':' + str(self.transport.getPeer().port)] = z['block_number']

		if chain.state.current == 'syncing': return

		if block_number == chain.m_blockheight():
			if chain.m_blockchain[block_number].blockheader.headerhash != headerhash:
				printL(( '>>> WARNING: headerhash mismatch from ', self.transport.getPeer().host))
				
				# initiate fork recovery and protection code here..
				# call an outer function which sets a flag and scrutinises the chains from all connected hosts to see what is going on..
				# again need to think this one through in detail..
						
				return

		if block_number > chain.m_blockheight():		
			return

		if len(chain.m_blockchain) == 1 and self.factory.genesis == 0:
			self.factory.genesis = 1										# set the flag so that no other Protocol instances trigger the genesis stake functions..
			printL(( 'genesis pos countdown to block 1 begun, 60s until stake tx circulated..'))
			reactor.callLater(1, pre_pos_1)
			return
				
		elif len(chain.m_blockchain) == 1 and self.factory.genesis == 1:	#connected to multiple hosts and already passed through..
			return

	def BN(self, data):			#request for block (n)
		if int(data) <= chain.m_blockheight():
			printL(( '<<<Sending block number', str(int(data)), str(len(chain.json_bytestream(chain.m_get_block(int(data))))),' bytes', 'to node: ', self.transport.getPeer().host))
			self.transport.write(self.wrap_message('BK',chain.json_bytestream_bk(chain.m_get_block(int(data)))))
			return
		else:
			if int(data) >= chain.m_blockheight():
				printL(( 'BN for a blockheight greater than local chain length..'))
				return
			else:
				printL(( 'BN request without valid block number', data, '- closing connection'))
				self.transport.loseConnection()
				return
		
	def FB(self, data):		#Fetch Request for block
		data = int(data)
		printL (( ' REqeust for ', data, ' by ', self.identity ))
		if data > 0 and data <= chain.block_chain_buffer.height():
			chain.block_chain_buffer.send_block(data, self.transport, self.wrap_message)
		else:
			self.transport.write(self.wrap_message('PB',data))
			if data > chain.height():
				printL(( 'FB for a blocknumber is greater than the local chain length..' ))
				return


	def FH(self, data):		#Fetch Block Headerhash
		data = int(data)
		if data > 0 and data <= chain.height():
			mini_block = {}
			printL(( '<<<Pushing block headerhash of block number ', str(data), ' to node: ', self.transport.getPeer().host ))
			mini_block['headerhash'] = chain.m_get_block(data).blockheader.headerhash
			mini_block['blocknumber'] = data
			self.transport.write(self.wrap_message('PH',chain.json_bytestream_ph(mini_block)))
		else:
			if data > chain.height():
				printL(( 'FH for a blocknumber is greater than the local chain length..' ))
				return

	def PO(self, data):
		if data[0:2] == 'NG':
			y = 0
			for entry in chain.ping_list:
				if entry['node'] == self.transport.getPeer().host:
					entry['ping (ms)'] = (time.time()-chain.last_ping)*1000
					y = 1
			if y == 0:
				chain.ping_list.append({'node': self.transport.getPeer().host, 'ping (ms)' : (time.time()-chain.last_ping)*1000})

	def PI(self, data):
		if data[0:2] == 'NG':
			self.transport.write(self.wrap_message('PONG'))
		else:
			self.transport.loseConnection()
			return

	def PL(self, data):			#receiving a list of peers to save into peer list..
		self.recv_peers(data)

	def RT(self):
		'<<< Transaction_pool to peer..'
		for t in chain.transaction_pool:
			f.send_tx_to_peers(t)
		return

	def PE(self):			#get a list of connected peers..need to add some ddos and type checking proteection here..
		self.get_peers()

	def VE(self, data=None):
		if not data:
			self.transport.write(self.wrap_message('VE',chain.version_number))
		else:
			self.version = str(data)
			printL(( self.transport.getPeer().host, 'version: ', data))
		return

	def R1(self, data):							#receive a reveal_one message sent out after block receipt or creation (could be here prior to the block!)
		if chain.state.current != 'synced':
			return
		z = chain.json_decode(data)
		if not z:
			return
		block_number = z['block_number']
		headerhash = z['headerhash'].encode('latin1')
		stake_address = z['stake_address'].encode('latin1')
		vote_hash = z['vote_hash'].encode('latin1')
		reveal_one = z['reveal_one'].encode('latin1')

		if block_number<=chain.height():
			return

		for entry in chain.stake_reveal_one:	#already received, do not relay.
			if entry[3] == reveal_one:
				return

		if len(chain.stake_validator_latency) > 20:
			del chain.stake_validator_latency[min(chain.stake_validator_latency.keys())]

		y=0
		if chain.state.epoch_diff == 0:
			#printL (( chain.block_chain_buffer.stake_list_get(z['block_number']) ))
			for s in chain.block_chain_buffer.stake_list_get(z['block_number']):
				if s[0] == stake_address:
					y=1
					reveal_one_tmp = chain.reveal_to_terminator(reveal_one, block_number)
					vote_hash_tmp = chain.reveal_to_terminator(vote_hash, block_number)
					reveal_hash_terminator, vote_hash_terminator = chain.select_hashchain(last_block_headerhash=chain.block_chain_buffer.get_strongest_headerhash(block_number-1), stake_address=stake_address, blocknumber = z['block_number'])
					if vote_hash_tmp != vote_hash_terminator:
						printL(( self.identity, ' vote hash doesnt hash to stake terminator', 'vote', vote_hash, 'nonce', s[2], 'hash_term', vote_hash_terminator))
						return
					if reveal_one_tmp != reveal_hash_terminator:
						printL(( self.identity, ' reveal doesnt hash to stake terminator', 'reveal', reveal_one, 'nonce', s[2], 'hash_term', reveal_hash_terminator))
						return
			if y==0:
				printL(( 'stake address not in the stake_list' ))
				return

		if len(r1_time_diff)>2:
			del r1_time_diff[min(r1_time_diff.keys())]

		r1_time_diff[block_number].append(int(time.time()*1000))

		printL(( '>>> POS reveal_one:', self.transport.getPeer().host, stake_address, str(block_number), reveal_one))
		score = chain.score(stake_address, reveal_one, blocknumber = z['block_number'])

		if score == None:
			printL (( 'Score None for stake_address ', stake_address, ' reveal_one ', reveal_one ))
			return

		if score != float(z['weighted_hash']):
			printL (( 'Weighted_hash didnt match' ))
			printL (( 'Expected : ', str(score) ))
			printL (( 'Found : ', str(z['weighted_hash']) ))
			return

		epoch = block_number/c.blocks_per_epoch
		epoch_PRF = chain.block_chain_buffer.get_epoch_PRF(z['block_number'])
		#PRF = chain.epoch_PRF[chain.block_chain_buffer.height()+1-(epoch*c.blocks_per_epoch)]
		PRF = epoch_PRF[z['block_number']-(epoch*c.blocks_per_epoch)]

		if PRF != z['PRF']:
			printL (( 'PRF didnt match' ))
			printL (( 'Expected : ', str(PRF) ))
			printL (( 'Found : ', str(z['PRF']) ))
			return

		sv_hash = chain.get_stake_validators_hash()
		#if sv_hash != z['SV_hash']:
		#	printL (( 'SV_hash didnt match' ))
		#	printL (( 'Expected : ', sv_hash ))
		#	printL (( 'Found : ', z['SV_hash'] ))
		#	return

		chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one, score])

		if chain.state.current == 'synced':
			for peer in self.factory.peers:
				if peer != self:
					peer.transport.write(self.wrap_message('R1',chain.json_encode(z)))	#relay
			
		return

	def IP(self, data):								#fun feature to allow geo-tagging on qrl explorer of test nodes..reveals IP so optional..
		if not data:
			if self.factory.ip_geotag == 1:
				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message('IP',self.transport.getHost().host))
		else:
			if data not in chain.ip_list:
				chain.ip_list.append(data)
				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message('IP',self.transport.getHost().host))

		return


	def recv_peers(self, json_data):
		data = chain.json_decode(json_data)
		new_ips = []
		for ip in data:
				new_ips.append(ip.encode('latin1'))
		peers_list = chain.state_get_peers()
		printL(( self.transport.getPeer().host, 'peers data received: ', new_ips))
		for node in new_ips:
				if node not in peers_list:
					if node != self.transport.getHost().host:
						peers_list.append(node)
						reactor.connectTCP(node, 9000, f)
		chain.state_put_peers(peers_list)
		chain.state_save_peers()
		return

	def get_latest_block_from_connection(self):
		printL(( '<<<Requested last block from', self.transport.getPeer().host))
		self.transport.write(self.wrap_message('LB'))
		return

	def get_m_blockheight_from_connection(self):
		printL(( '<<<Requesting blockheight from', self.transport.getPeer().host))
		self.transport.write(self.wrap_message('MB'))
		return

	def send_m_blockheight_to_peer(self):
		z = {}
		z['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash
		z['block_number'] = 0
		if len(chain.m_blockchain):				
			z['block_number'] = chain.m_blockchain[-1].blockheader.blocknumber 			
		self.transport.write(self.wrap_message('CB',chain.json_encode(z)))
		return

	def get_version(self):
		printL(( '<<<Getting version', self.transport.getPeer().host))
		self.transport.write(self.wrap_message('VE'))
		return

	def get_peers(self):
		printL(( '<<<Sending connected peers to', self.transport.getPeer().host))
		peers_list = []
		for peer in self.factory.peers:
			peers_list.append(peer.transport.getPeer().host)
		self.transport.write(self.wrap_message('PL',chain.json_encode(peers_list)))
		return

	def get_block_n(self, n):
		printL(( '<<<Requested block: ', str(n), 'from ', self.transport.getPeer().host))
		self.transport.write(self.wrap_message('BN',str(n)))
		return

	def fetch_block_n(self, n):
		if self.last_requested_blocknum != n:
			self.fetch_tried = 0
		self.fetch_tried += 1 #TODO: remove from target_peers if tried is greater than x
		self.last_requested_blocknum = n
		printL(( '<<<Fetching block: ', n, 'from ', self.transport.getPeer().host, ':', self.transport.getPeer().port ))
		self.transport.write(self.wrap_message('FB',str(n)))
		return

	def fetch_FMBH(self):
		printL(( '<<<Fetching FMBH from : ', self.identity ))
		self.transport.write(self.wrap_message('FMBH'))

	def fetch_headerhash_n(self, n):
		printL(( '<<<Fetching headerhash of block: ', n, 'from ', self.transport.getPeer().host, ':', self.transport.getPeer().port ))
		self.transport.write(self.wrap_message('FH',str(n)))
		return

	def wrap_message(self, type, data=None):
		jdata = {}
		jdata['type'] = type
		if data:
			jdata['data'] = data
		str_data = json.dumps(jdata)
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(str_data))+chr(0)+str_data+chr(0)+chr(0)+chr(255)

	def clean_buffer(self, reason=None, upto=None):
		if reason:
			printL(( reason))
		if upto:
			self.buffer = self.buffer[upto:] 			#Clean buffer till the value provided in upto
		else:
			self.buffer = ''					#Clean buffer completely

	def parse_buffer(self):
		if len(self.buffer)==0:
			return False

		d = self.buffer.find(chr(255)+chr(0)+chr(0))					#find the initiator sequence
		num_d = self.buffer.count(chr(255)+chr(0)+chr(0))				#count the initiator sequences

		if d == -1:														#if no initiator sequences found then wipe buffer..
			self.clean_buffer(reason='Message data without initiator')
			return False

		self.buffer = self.buffer[d:]									#delete data up to initiator

		if len(self.buffer)<8:							#Buffer is still incomplete as it doesn't have message size
			return False

		try: m = struct.unpack('>L', self.buffer[3:7])[0]			#is m length encoded correctly?
		except:
				if num_d > 1:										#if not, is this the only initiator in the buffer?
					self.buffer = self.buffer[3:]
					d = self.buffer.find(chr(255)+chr(0)+chr(0))
					self.clean_buffer(reason='Struct.unpack error attempting to decipher msg length, next msg preserved', upto=d)		#no
					return True
				else:
					self.clean_buffer(reason='Struct.unpack error attempting to decipher msg length..')		#yes
				return False

		if m > 500*1024:							#check if size is more than 500 KB
			if num_d > 1:
				self.buffer = self.buffer[3:]
				d = self.buffer.find(chr(255)+chr(0)+chr(0))
				self.clean_buffer(reason='Size is more than 500 KB, next msg preserved', upto=d)
				return True
			else:
				self.clean_buffer(reason='Size is more than 500 KB')
			return False

		e = self.buffer.find(chr(0)+chr(0)+chr(255))				#find the terminator sequence

		if e ==-1:							#no terminator sequence found
			if len(self.buffer) > 8+m+3:
				if num_d >1:										#if not is this the only initiator sequence?
					self.buffer = self.buffer[3:]
					d = self.buffer.find(chr(255)+chr(0)+chr(0))
					self.clean_buffer(reason='Message without appropriate terminator, next msg preserved', upto=d)						#no
					return True
				else:
					self.clean_buffer(reason='Message without initiator and terminator')					#yes
			return False

		if e != 3+5+m:								#is terminator sequence located correctly?
			if num_d >1:											#if not is this the only initiator sequence?
				self.buffer = self.buffer[3:]
				d = self.buffer.find(chr(255)+chr(0)+chr(0))
				self.clean_buffer(reason='Message terminator incorrectly positioned, next msg preserved', upto=d)						#no
				return True
			else:
				self.clean_buffer(reason='Message terminator incorrectly positioned')						#yes
			return False

		self.messages.append(self.buffer[8:8+m])					#if survived the above then save the msg into the self.messages
		self.buffer = self.buffer[8+m+3:]							#reset the buffer to after the msg
		return True

	def dataReceived(self, data):		# adds data received to buffer. then tries to parse the buffer twice..

		self.buffer += data

		for x in range(50):
			if self.parse_buffer()==False:
				break
			else:
				for msg in self.messages:
					self.parse_msg(msg)
				del self.messages[:]
		return

	def connectionMade(self):
		peerHost, peerPort = self.transport.getPeer().host, self.transport.getPeer().port
		self.identity = peerHost+":"+str(peerPort)
		self.factory.connections += 1
		self.factory.peers.append(self)
		peer_list = chain.state_get_peers()
		if self.transport.getPeer().host == self.transport.getHost().host:
						if self.transport.getPeer().host in peer_list:
								printL(( 'Self in peer_list, removing..'))
								peer_list.remove(self.transport.getPeer().host)
								chain.state_put_peers(peer_list)
								chain.state_save_peers()
						self.transport.loseConnection()
						return
		
		if self.transport.getPeer().host not in peer_list:
			printL(( 'Adding to peer_list'))
			peer_list.append(self.transport.getPeer().host)
			chain.state_put_peers(peer_list)
			chain.state_save_peers()
		printL(( '>>> new peer connection :', self.transport.getPeer().host, ' : ', str(self.transport.getPeer().port)))

		self.get_m_blockheight_from_connection()
		self.get_peers()
		self.get_version()

		# here goes the code for handshake..using functions within the p2pprotocol class
		# should ask for latest block/block number.
		

	def connectionLost(self, reason):
		self.factory.connections -= 1
		printL(( self.transport.getPeer().host,  ' disconnected. ', 'remainder connected: ', str(self.factory.connections))) #, reason 
		self.factory.peers.remove(self)
		if self.identity in self.factory.target_peers:
			del self.factory.target_peers[self.identity]
		host_port = self.transport.getPeer().host + ':' + str(self.transport.getPeer().port)
		if host_port in self.factory.peers_blockheight:
			del self.factory.peers_blockheight[host_port]
		if self.factory.connections == 0:
			reactor.callLater(60,f.connect_peers)

	

	def recv_tx(self, json_tx_obj):
		
		try: tx = chain.SimpleTransaction().json_to_transaction(json_tx_obj)
		except: 
				printL(( 'tx rejected - unable to decode serialised data - closing connection'))
				self.transport.loseConnection()
				return

		if tx.txhash in chain.prev_txpool or tx.txhash in chain.pending_tx_pool_hash:
			return

		del chain.prev_txpool[0]
		chain.prev_txpool.append(tx.txhash)
		
		for t in chain.transaction_pool:			#duplicate tx already received, would mess up nonce..
			if tx.txhash == t.txhash:
				return

		chain.update_pending_tx_pool(tx, self)
		
		return


class p2pFactory(ServerFactory):

	protocol = p2pProtocol

	def __init__(self):
		self.stake = True			#default to mining off as the wallet functions are not that responsive at present with it enabled..
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
		self.ip_geotag = 1			# to be disabled in main release as reveals IP..
		self.last_reveal_one = None
		self.last_reveal_two = None
		self.last_reveal_three = None

# factory network functions
	
	def get_block_a_to_b(self, a, b):
		printL(( '<<<Requested blocks:', a, 'to ', b, ' from peers..'))
		l = range(a,b)
		for peer in self.peers:
			if len(l) > 0:
				peer.transport.write(self.f_wrap_message('BN',str(l.pop(0))))
			else:
				return				

	def get_block_n_random_peer(self,n):
		printL(( '<<<Requested block: ', n, 'from random peer.'))
		random.choice(self.peers).get_block_n(n)
		return


	def get_block_n(self, n):
		printL(( '<<<Requested block: ', n, 'from peers.'))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('BN',str(n)))
		return

	def get_m_blockheight_from_random_peer(self):
		printL(( '<<<Requested blockheight from random peer.'))
		random.choice(self.peers).get_m_blockheight_from_connection()
		return

	def get_blockheight_map_from_peers(self):
		printL(( '<<<Requested blockheight_map from peers.'))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('BM'))
		return

	def get_m_blockheight_from_peers(self):
		for peer in self.peers:
			peer.get_m_blockheight_from_connection()
		return

	def send_m_blockheight_to_peers(self):
		printL(( '<<<Sending blockheight to peers.'))
		for peer in self.peers:
			peer.send_m_blockheight_to_peer()
		return

	def f_wrap_message(self, type, data=None):
		jdata = {}
		jdata['type'] = type
		if data:
			jdata['data'] = data
		str_data = json.dumps(jdata)
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(str_data))+chr(0)+str_data+chr(0)+chr(0)+chr(255)

	def send_st_to_peers(self, st):
		printL(( '<<<Transmitting ST:', st.epoch ))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('ST',st.transaction_to_json()))
		return

	def send_tx_to_peers(self, tx):
		printL(( '<<<Transmitting TX: ', tx.txhash))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('TX',tx.transaction_to_json()))
		return

	def send_reboot(self, json_hash):
		printL(( '<<<Transmitting Reboot Command' ))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('reboot', json_hash))
		return

	# transmit reveal_one hash.. (node cast lottery vote)

	def send_stake_reveal_one(self, blocknumber=None):
		z = {}
		z['stake_address'] = chain.mining_address
		z['block_number'] = blocknumber
		if not z['block_number']:
			z['block_number'] = chain.block_chain_buffer.height() + 1				#next block..
		z['headerhash'] = chain.block_chain_buffer.get_strongest_headerhash(z['block_number']-1)				#demonstrate the hash from last block to prevent building upon invalid block..
		epoch = z['block_number']/c.blocks_per_epoch
		#z['reveal_one'] = chain.hash_chain[-1][:-1][::-1][z['block_number']-(epoch*c.blocks_per_epoch)]
		hash_chain = chain.block_chain_buffer.hash_chain_get(z['block_number'])
		z['reveal_one'] = hash_chain[-1][:-1][::-1][z['block_number']-(epoch*c.blocks_per_epoch)]
		z['vote_hash'] = None
		z['weighted_hash'] = None
		epoch_PRF = chain.block_chain_buffer.get_epoch_PRF(blocknumber)
		z['PRF'] = epoch_PRF[z['block_number']-(epoch*c.blocks_per_epoch)]
		z['SV_hash'] = chain.get_stake_validators_hash()
		#z['reveal_one'] = chain.hash_chain[:-1][::-1][z['block_number']-(epoch*10000)]


		_, hash = chain.select_hashchain(last_block_headerhash=chain.block_chain_buffer.get_strongest_headerhash(z['block_number']-1), stake_address=chain.mining_address, blocknumber=z['block_number'])


		for hashes in hash_chain:
			if hashes[-1] == hash:
				z['vote_hash'] = hashes[:-1][::-1][z['block_number']-(epoch*c.blocks_per_epoch)]
				break

		if z['reveal_one'] == None or z['vote_hash'] == None:
			printL (( 'reveal_one or vote_hash None for stake_address: ', z['stake_address'], ' selected hash:', hash ))
			printL (( 'reveal_one', z['reveal_one'] ))
			printL (( 'vote_hash', z['vote_hash'] ))
			printL (( 'hash', hash ))
			return

		z['weighted_hash'] = chain.score(z['stake_address'], z['reveal_one'], blocknumber = z['block_number'])

		#rkey = random_key()
		#z['reveal_two'] = sha256(z['reveal_one']+rkey)

		y=False
		tmp_stake_reveal_one = []
		for r in chain.stake_reveal_one:											#need to check the reveal list for existence already, if so..reuse..
			if r[0] == chain.mining_address:
				if r[1] == z['headerhash']:
					if r[2] == z['block_number']:
						if y==True:
							continue						#if repetition then remove..
						else:
							z['reveal_one'] = r[3]
							y=True
			tmp_stake_reveal_one.append(r)
		
		chain.stake_reveal_one = tmp_stake_reveal_one
		printL(( '<<<Transmitting POS reveal_one'))

		self.last_reveal_one = z
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('R1',chain.json_encode(z)))
		score = chain.score(chain.mining_address, z['reveal_one'], blocknumber = z['block_number'])
		if y==False:
			chain.stake_reveal_one.append([z['stake_address'], z['headerhash'], z['block_number'], z['reveal_one'], score])		#don't forget to store our reveal in stake_reveal_one
		return z['reveal_one']#, z['block_number']

	def send_last_stake_reveal_one(self):
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('R1',chain.json_encode(self.last_reveal_one)))

	def ip_geotag_peers(self):
		printL(( '<<<IP geotag broadcast'))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('IP'))
		return

	def ping_peers(self):
		printL(( '<<<Transmitting network PING'))
		chain.last_ping = time.time()
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('PING'))
		return

	# send POS block to peers..

	def send_stake_block(self, block_obj):
		printL(( '<<<Transmitting POS created block', str(block_obj.blockheader.blocknumber), block_obj.blockheader.headerhash))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('S4',chain.json_bytestream(block_obj)))
		return

	# send/relay block to peers

	def send_block_to_peers(self, block, peer_identity=None):
		printL(( '<<<Transmitting block: ', block.blockheader.headerhash))
		for peer in self.peers:
			if peer_identity == peer.identity:
				continue
			peer_info = peer.transport.getPeer()
			printL (('<<<Block Transmitted to ', peer_info.host, ':', peer_info.port ))
			peer.transport.write(self.f_wrap_message('BK',chain.json_bytestream_bk(block)))
		return

	# request transaction_pool from peers

	def get_tx_pool_from_peers(self):
		printL(( '<<<Requesting TX pool from peers..'))
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('RT'))
		return

	# connection functions

	def connect_peers(self):
		printL(( '<<<Reconnecting to peer list:'))
		for peer in chain.state_get_peers():
			reactor.connectTCP(peer, 9000, f)

	def clientConnectionLost(self, connector, reason):		#try and reconnect
		#printL(( 'connection lost: ', reason, 'trying reconnect'
		#connector.connect()
		return

	def clientConnectionFailed(self, connector, reason):
		#printL(( 'connection failed: ', reason
		return

	def startedConnecting(self, connector):
		#printL(( 'Started to connect.', connector
		return


class WalletFactory(ServerFactory):

	protocol = WalletProtocol

	def __init__(self, stuff):
		self.newaddress = 0
		self.stuff = stuff
		self.recn = 0
		self.maxconnections = 1
		self.connections = 0
		self.last_cmd = 'help'

class ApiFactory(ServerFactory):

	protocol = ApiProtocol

	def __init__(self):
		self.connections = 0
		self.api = 1
		pass

if __name__ == "__main__":
	start_time = time.time()
	chain.block_chain_buffer = None #chain.ChainBuffer()

	printL(( 'Reading chain..'))
	chain.m_load_chain()
	printL(( str(len(chain.m_blockchain))+' blocks'))
	printL(( 'Verifying chain'))
	printL(( 'Building state leveldb' ))

	printL(( 'Loading node list..'))			# load the peers for connection based upon previous history..
	chain.state_load_peers()
	printL(( chain.state_get_peers()))

	stuff = 'QRL node connection established. Try starting with "help"'+'\r\n'
	printL(( '>>>Listening..'))
	
	f = p2pFactory()
	api = ApiFactory()

	reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
	reactor.listenTCP(9000, f)
	reactor.listenTCP(8080, api)

	restart_monitor_bk(80)

	printL(( 'Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"'))
	printL(( '<<<Connecting to nodes in peer.dat'))

	f.connect_peers()
	reactor.callLater(20, unsynced_logic)

	reactor.run()
