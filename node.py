# QRL testnet node..
# -features POS, quantum secure signature scheme..

__author__ = 'pete'
import time, struct, random, copy, decimal
import chain, wallet

from twisted.internet.protocol import ServerFactory, Protocol 
from twisted.internet import reactor
from merkle import sha256, numlist, hexseed_to_seed, mnemonic_to_seed, GEN_range, random_key
from operator import itemgetter
from collections import Counter
from math import ceil

version_number = "alpha/0.04a"

cmd_list = ['balance', 'mining', 'seed', 'hexseed', 'recoverfromhexseed', 'recoverfromwords', 'stakenextepoch', 'stake', 'address', 'wallet', 'send', 'mempool', 'getnewaddress', 'quit', 'exit', 'search' ,'json_search', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight', 'json_block']
api_list = ['block_data','stats', 'ip_geotag','exp_win','txhash', 'address', 'empty', 'last_tx', 'stake_reveal_ones', 'last_block', 'richlist', 'ping', 'stake_commits', 'stake_reveals', 'stake_list', 'stakers', 'next_stakers']


def parse(data):
		return data.replace('\r\n','')

# pos functions. an asynchronous loop. 

# first block 1 is created with the stake list for epoch 0 decided from circulated st transactions

def pre_pos_1(data=None):		# triggered after genesis for block 1..
	print 'pre_pos_1'
	# are we a staker in the stake list?

	if chain.mining_address in chain.m_blockchain[0].stake_list:
		print 'mining address:', chain.mining_address,' in the genesis.stake_list'
		print 'hashchain terminator: ', chain.hash_chain[-1]
		st = chain.CreateStakeTransaction(chain.hash_chain[-1])
		wallet.f_save_winfo()
		chain.add_st_to_pool(st)
		f.send_st_to_peers(st)			#send the stake tx to generate hashchain terminators for the staker addresses..
		print 'await delayed call to build staker list from genesis'
		reactor.callLater(5, pre_pos_2, st)
		return

	print 'not in stake list..no further pre_pos_x calls'
	return

def pre_pos_2(data=None):	
	print 'pre_pos_2'

	# assign hash terminators to addresses and generate a temporary stake list ordered by st.hash..

	tmp_list = []

	for st in chain.stake_pool:
		if st.txfrom in chain.m_blockchain[0].stake_list:
			tmp_list.append([st.txfrom, st.hash, 0])
	
	chain.stake_list = sorted(tmp_list, key=itemgetter(1))

	numlist(chain.stake_list)

	print 'genesis stakers ready = ', len(chain.stake_list),'/',len(chain.m_blockchain[0].stake_list)
	print 'node address:', chain.mining_address

	if len(chain.stake_list) < len(chain.m_blockchain[0].stake_list):		# stake pool still not full..reloop..
		f.send_st_to_peers(data)
		print 'waiting for stakers.. retry in 5s'
		reactor.callID = reactor.callLater(5, pre_pos_2, data)
		return

	for s in chain.stake_list:
		if s[0] == chain.mining_address:
			spos = chain.stake_list.index(s)
	
	chain.epoch_prf = chain.pos_block_selector(chain.m_blockchain[-1].stake_seed, len(chain.stake_pool))	 #Use PRF to decide first block selector..
	#def GEN_range(SEED, start_i, end_i, l=32): 
	chain.epoch_PRF = GEN_range(chain.m_blockchain[-1].stake_seed, 1, 10000, 32)

	print 'epoch_prf:', chain.epoch_prf[1]
	print 'spos:', spos

	if spos == chain.epoch_prf[1]:
		print 'designated to create block 1: building block..'

		# create the genesis block 2 here..

		b = chain.m_create_block(chain.hash_chain[-2])
		#chain.json_print(b)
		print chain.validate_block(b)
		if chain.m_add_block(b) == True:
			f.send_block_to_peers(b)
			f.get_m_blockheight_from_peers()
			print '**POS commit call later 30 (genesis)...**'
			f.send_stake_reveal_one()
			reactor.callLater(15, reveal_two_logic)
									
	else:
		print 'await block creation by stake validator:', chain.stake_list[chain.epoch_prf[1]][0]
		#f.send_st_to_peers(data)
	return



# we end up here exactly 30 seconds after the last block arrived or was created and sent out..
# collate the reveal_ones messages to decide the winning hash..send out reveal_two's with our vote..


def reveal_two_logic(data=None):
	print 'reveal_two_logic'
	#chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one, reveal_two]) 

	reveals = []

	for s in chain.stake_reveal_one:
		if s[1] == chain.m_blockchain[-1].blockheader.headerhash and s[2] == chain.m_blockchain[-1].blockheader.blocknumber+1:
			reveals.append(s[3])

	# are we forked and creating only our own blocks?

	if len(reveals) <= 1:
			print 'only received one reveal for this block..quitting reveal_two_logic'
			f.get_m_blockheight_from_peers()
			return

	# what is the PRF output and expected winner for this block?	

	winner = chain.cl_hex(chain.epoch_PRF[chain.m_blockchain[-1].blockheader.blocknumber+1], reveals)

	if f.stake == True:
		if chain.mining_address in [s[0] for s in chain.stake_list_get()]:
				f.send_stake_reveal_two(winner)

	if chain.mining_address in [s[0] for s in chain.stake_reveal_one]:
		for t in chain.stake_reveal_one:
			if t[0]==chain.mining_address:
				if t[2]==chain.m_blockchain[-1].blockheader.blocknumber+1:
					our_reveal = t[3]
					reactor.callIDR2 = reactor.callLater(15, reveal_three_logic, winner=winner, reveals=reveals, our_reveal=our_reveal)
					return
	
	reactor.callIDR2 = reactor.callLater(15, reveal_three_logic, winner=winner, reveals=reveals)
	return


# here ~30s after last block..
# collate the R2 messages to see if we are creating the block by network consensus..

def reveal_three_logic(winner, reveals, our_reveal=None):
	print 'reveal_three_logic'
	#chain.pos_d = [c[0][0], c[0][1], total_stakers, percentage_b, total_voted, total_staked, percentage_d, stake_address]

	if pos_d(chain.m_blockchain[-1].blockheader.blocknumber+1, chain.m_blockchain[-1].blockheader.headerhash) is False:
		print 'pos_d problem..with reveal_one or reveal_two..'
		reset_everything()
		return

#staked = decimal.Decimal((b/100000000.000000000)/(chain.db.total_coin_supply()/100000000.000000000)*100).quantize(decimal.Decimal('1.00'))

	print 'CONSENSUS:', chain.pos_d[1],'/', chain.pos_d[2],'(', chain.pos_d[3],'%)', 'voted/staked emission %:', chain.pos_d[6],'v/s ', chain.pos_d[4]/100000000.0, '/', chain.pos_d[5]/100000000.0  ,'for: ', chain.pos_d[0] 

	# does network agree? are we in agreement?

	if winner not in chain.pos_d or consensus_rules_met() is False:								#network disagrees with us..time to bug out..
		print 'winner not in pos_d - resetting all loops'
		reset_everything()
		return

	# we have got far enough to activate the pos_flag

	chain.pos_flag = [chain.m_blockchain[-1].blockheader.blocknumber+1, chain.m_blockchain[-1].blockheader.headerhash]
	
	# if we aren't staking this round and haven't produced a reveal hash

	#if our_reveal!=None:
	#	f.sync 
	#	print 'our_reveal=None'
	#	return

	# are we the winner? let's create the block then..

	if chain.pos_d[7]==chain.mining_address and chain.pos_d[0]==our_reveal:
		print 'CHOSEN BLOCK SELECTOR'
		f.sync = 1
		f.partial_sync = [0, 0]
		reactor.callLater(10, create_new_block, our_reveal, reveals)
	else:
		print 'CONSENSUS winner: ', chain.pos_d[7], 'hash ', chain.pos_d[0]
		print 'our_reveal', our_reveal
	return
	

def create_new_block(winner, reveals):
		print 'create_new_block'
		tx_list = []
		for t in chain.transaction_pool:
			tx_list.append(t.txhash)
		block_obj = chain.create_stake_block(tx_list, winner, reveals)

		if chain.m_add_block(block_obj) is True:				
			stop_all_loops()
			del chain.stake_reveal_one[:]					# as we have just created this there can be other messages yet for next block, safe to erase
			del chain.stake_reveal_two[:]
			f.send_block_to_peers(block_obj)				# relay the block

		else:
			print 'bad block'
			return
	
	# if staking
		post_block_logic()
		return


def pos_missed_block(data=None):
	print '** Missed block logic ** - trigger m_blockheight recheck..'
	f.get_m_blockheight_from_peers()
	f.send_m_blockheight_to_peers()
	return

def reset_everything(data=None):
	print '** resetting loops and emptying chain.stake_reveal_one, reveal_two, chain.pos_d and chain.expected_winner '
	stop_all_loops()
	del chain.stake_reveal_one[:]
	del chain.stake_reveal_two[:]
	del chain.expected_winner[:]
	del chain.pos_d[:]
	del chain.pos_flag[:]
	return


def stop_all_loops(data=None):
	print '** stopping timing loops **'
	try:	reactor.callIDR15.cancel()	#reveal loop
	except:	pass
	try:	reactor.callID.cancel()		#cancel the ST genesis loop if still running..
	except: pass
	try: 	reactor.callIDR2.cancel()
	except: pass
	try: 	reactor.callID2.cancel()		#cancel the soon to be re-called missed block logic..
	except: pass
	return

def stop_pos_loops(data=None):
	print '** stopping pos loops and resetting flags **'
	try:	reactor.callIDR15.cancel()	#reveal loop
	except:	pass
	try: 	reactor.callIDR2.cancel()
	except: pass
	try:	reactor.callID.cancel()		#cancel the ST genesis loop if still running..
	except: pass

	# flags
	del chain.pos_flag[:]
	del chain.pos_d[:]
	return

def start_all_loops(data=None):
	print '** starting loops **'
	reactor.callID2 = reactor.callLater(120, pos_missed_block)
	reactor.callIDR15 = reactor.callLater(15, reveal_two_logic)
	return

# remove old messages - this is only called when we have just added the last block so we know that messages related to this block and older are no longer necessary..

	#chain.stake_reveal_two.append([z['stake_address'],z['headerhash'], z['block_number'], z['reveal_one'], z['nonce'], z['winning_hash']])		
	#chain.stake_reveal_one.append([z['stake_address'],z['headerhash'], z['block_number'], z['reveal_one'], z['reveal_two'], rkey])
	
def filter_reveal_one_two():

	for s in chain.stake_reveal_one:
		if s[2] <= chain.m_blockchain[-1].blockheader.blocknumber:
			chain.stake_reveal_one.remove(s)

	for s in chain.stake_reveal_two:
		if s[2] <= chain.m_blockchain[-1].blockheader.blocknumber:
			chain.stake_reveal_two.remove(s)

	return


# supra factory block logic 

# pre block logic..

def pre_block_logic(block_obj):
	print 'pre_block_logic'

	# is the node in transition between f.sync 0 and 1 or in error recovery mode?


	if f.sync == 0:
		if f.partial_sync[0]==1:
			print 'partial_sync'
			if f.partial_sync[1]==chain.m_blockheight():
				if blockheight_map() == True:
					f.sync=1			# partial sync has happened but we may not be synchronised..
	
	f.partial_sync = [0,0]
	received_block_logic(block_obj)
	return

def received_block_logic(block_obj):

	if f.sync == 0:
		chain.recent_blocks.append(block_obj)
		synchronising_update_chain()
		return

	# rapid logic

	if block_obj.blockheader.headerhash == chain.m_blockchain[-1].blockheader.headerhash:
			return

	if block_obj.blockheader.blocknumber != chain.m_blockheight()+1:
			print '>>>BLOCK - out of order - need', str(chain.m_blockheight()+1), ' received ', str(block_obj.blockheader.blocknumber), block_obj.blockheader.headerhash#, ' from ', self.transport.getPeer().host
			f.get_m_blockheight_from_peers()
			return
	
	if block_obj.blockheader.prev_blockheaderhash != chain.m_blockchain[-1].blockheader.headerhash:
			print '>>>WARNING: FORK..'
			return

	# pos checks
	if block_obj.blockheader.blocknumber > 1:
		if block_meets_consensus(block_obj.blockheader) != True:
			return

	# validation and state checks, then housekeeping

	if chain.m_add_block(block_obj) is True:				
		f.send_block_to_peers(block_obj)
		
		post_block_logic()
	return


# post block logic we initiate the next POS cycle, send R1, send ST, reset POS flags and remove unnecessary messages in chain.stake_reveal_one and _two..

def post_block_logic():

	stop_all_loops()
	start_all_loops()

	filter_reveal_one_two()

	del chain.pos_flag[:]
	del chain.pos_d[:]
	del chain.expected_winner[:]

	if f.stake == True:
		if chain.mining_address in [s[0] for s in chain.stake_list_get()]:
				f.send_stake_reveal_one()
		if chain.mining_address not in [s[0] for s in chain.next_stake_list_get()]:
				f.send_st_to_peers(chain.CreateStakeTransaction())

	return


# network consensus rules set here for acceptable stake validator counts and weight based upon address balance..
# to be updated..

def block_meets_consensus(blockheader_obj):

	if len(chain.pos_flag)==0:
		print 'POS reveal_three_logic not activated..'
		return False

	if chain.pos_flag[0]!=blockheader_obj.blocknumber or chain.pos_flag[1]!=blockheader_obj.prev_blockheaderhash:
		print 'POS reveal_three_logic not activated for this block..'
		return False

	#print 'CONSENSUS:', chain.pos_d[1],'/', chain.pos_d[2],'(', chain.pos_d[3],'%)', 'voted/staked emission %:', chain.pos_d[6], ' for: ', chain.pos_d[0] 

	# check consensus rules..stake validators have to be in 75% agreement or if less then 75% of funds have to be agreement..

	if consensus_rules_met() is False:
		return False
	
	# is it the correct winner?

	if blockheader_obj.hash != chain.pos_d[0]:
		print 'Winning hash does not match consensus..rejected'
		return False

	if blockheader_obj.stake_selector != chain.pos_d[7]:
		print 'Stake selector does not match consensus..rejected'
		return False

	return True


# consensus rules..

def consensus_rules_met():

	if chain.pos_d[3] < 75:
		if chain.pos_d[6] < 75:
			print 'Network consensus inadequate..rejected'
			return False
	return True


# synchronisation functions.. use random sampling of connected nodes to reduce chatter between nodes..


def get_synchronising_blocks(block_number):
	f.sync = 0
	f.requested[1] += 1
	stop_all_loops()
	
	behind = block_number-chain.m_blockheight()
	peers = len(f.peers)

	if f.requested[0] == chain.m_blockheight()+1:
		if f.requested[1] <= len(f.peers):
			return

	print 'local node behind connection by ', behind, 'blocks - synchronising..'
	f.requested = [chain.m_blockheight()+1, 0]
	f.get_block_n_random_peer(chain.m_blockheight()+1)
	return



def synchronising_update_chain(data=None):
	print 'sync update chain'
	
	chain.recent_blocks.sort(key=lambda x: x.blockheader.blocknumber)			# sort the contents of the recent_blocks pool in ascending block number order..

	for b in chain.recent_blocks:
		if b.blockheader.blocknumber <= chain.m_blockheight():
			chain.recent_blocks.remove(b)
		if b.blockheader.blocknumber != chain.m_blockheight()+1:
			pass
		else:
			if b.blockheader.prev_blockheaderhash != chain.m_blockchain[-1].blockheader.headerhash:
				chain.recent_blocks.remove(b)	#forked blocks?
			else:
				chain.m_add_block(b)

	del chain.recent_blocks[:]
	f.get_m_blockheight_from_random_peer()
	return


# blockheight map for connected nodes - when the blockheight seems up to date after a sync or error, we check all connected nodes to ensure all on same chain/height..
# note - may not return correctly during a block propagation..
# once working alter to identify fork better..

def blockheight_map():

	#i = [block_number, headerhash, self.transport.getPeer().host]

	print 'blockheight_map:'
	print chain.blockheight_map

	# first strip out any laggards..

	for s in chain.blockheight_map:
		if s[0]<chain.m_blockheight():
			chain.blockheight_map.remove(s)

	bmap_fail = 0

	# next identify any node entries which are not exactly correct..

	for s in chain.blockheight_map:
		if s[0]==chain.m_blockheight() and s[1]==chain.m_blockchain[-1].blockheader.headerhash:
			print 'node: ', s[2], '@', s[0], 'w/:', s[1], 'OK'
		elif s[0] > chain.m_blockheight():
			print 'warning..', s[2], 'at blockheight', s[0]
			bmap_fail = 1

	# wipe it..

	del chain.blockheight_map[:]

	if bmap_fail == 1:
		return False

	return True


# rank the winning hashes for the current block number, by number, by address balance and both..after receipt of each valid R2 msg

def pos_d(block_number, headerhash):

	#chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one, reveal_two]) 
	#chain.stake_reveal_two.append([stake_address, headerhash, block_number, reveal_one, nonce, winning_hash]) 

	p = []
	for s in chain.stake_reveal_one:
		if s[1]==headerhash and s[2]==block_number:
			p.append(chain.state_balance(s[0]))

	if len(p) <= 1:
		return False

	total_stakers = len(p)
	total_staked = sum(p)


	l = []
	for s in chain.stake_reveal_two:
		if s[1]==headerhash and s[2]==block_number:
			l.append([chain.state_balance(s[0]),s[5]])

	if len(l) <=1: 
		return False

	total_voters = len(l)
	
	c = Counter([s[1] for s in l]).most_common(2)		#list containing tuple count of (winning hash, count) - first two..
	
	# all votes same..should be this every time
	if len(c) != 1 :
		print 'warning, more than one winning hash is being circulated by incoming R2 messages..'

	for s in chain.stake_reveal_one:
		if s[3]==c[0][0]:
			stake_address = s[0]

	percentage_a = decimal.Decimal(c[0][1])/decimal.Decimal(total_voters)*100			#percentage of voters choosing winning hash
	percentage_b = decimal.Decimal(c[0][1])/decimal.Decimal(total_stakers)*100			#percentage of voters choosing winning hash/total stakers
	percentage_c = decimal.Decimal(total_voters)/decimal.Decimal(total_stakers)*100		#percentage of overall voters to overall stakers..

	total_voted=0
	for s in l:
		if s[1]==c[0][0]:
			total_voted+=s[0]

	percentage_d = decimal.Decimal(total_voted)/decimal.Decimal(total_staked)*100	


	# as messages arrive we store the results in chain.pos_d
	chain.pos_d = [c[0][0], c[0][1], total_stakers, percentage_b, total_voted, total_staked, percentage_d, stake_address]

	return True


# factories and protocols..

class ApiProtocol(Protocol):

	def __init__(self):
		pass

	def parse_cmd(self, data):

		data = data.split()			#typical request will be: "GET /api/{command}/{parameter} HTTP/1.1"
		
		#print data

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
		print '<<< API expected winner call'
		return chain.exp_win(data)

	def ping(self, data=None):
		print '<<< API network latency ping call'
		f.ping_peers()									 # triggers ping for all connected peers at timestamp now. after pong response list is collated. previous list is delivered.
		pings = {}
		pings['status'] = 'ok'
		pings['peers'] = {}
		pings['peers'] = chain.ping_list
		return chain.json_print_telnet(pings)

	def stakers(self, data=None):
		print '<<< API stakers call'
		return chain.stakers(data)

	def next_stakers(self, data=None):
		print '<<< API next_stakers call'
		return chain.next_stakers(data)

	def stake_commits(self, data=None):
		print '<<< API stake_commits call'
		return chain.stake_commits(data)

	def stake_reveals(self, data=None):
		print '<<< API stake_reveals call'
		return chain.stake_reveals(data)

	def stake_reveal_ones(self, data=None):
		print '<<< API stake_reveal_ones'
		return chain.stake_reveal_ones(data)

	def richlist(self,data=None):
		print '<<< API richlist call'
		return chain.richlist(data)

	def last_block(self, data=None):
		print '<<< API last_block call'
		return chain.last_block(data)

	def last_tx(self, data=None):
		print '<<< API last_tx call'
		return chain.last_tx(data)

	def ip_geotag(self, data=None):
		print '<<< API ip_geotag call'
		f.ip_geotag_peers()
		return chain.ip_geotag(data)

	def empty(self, data=None):
		error = {'status': 'error','error' : 'no method supplied', 'methods available' : 'block_data, stats, txhash, address, last_tx, last_block, richlist, ping, stake_commits, stake_reveals, stakers, next_stakers'}
		return chain.json_print_telnet(error)

	def block_data(self, data=None):				# if no data = last block ([-1])			#change this to add error.. 
		error = {'status': 'error', 'error' : 'block not found', 'method': 'block_data', 'parameter' : data}
		print '<<< API block data call', data	
		if not data:
			#return chain.json_print_telnet(chain.m_get_last_block())
			data = chain.m_get_last_block()
			data1 = copy.deepcopy(data)
			data1.status = 'ok'
			return chain.json_print_telnet(data1)
		try: int(data)														# is the data actually a number?
		except: 
			return chain.json_print_telnet(error)
		#js_bk = chain.json_print_telnet(chain.m_get_block(int(data)))
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
		print '<<< API stats call'

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

		#print 'mean', z/len(chain.m_blockchain[-100:]), 'max', max(t), 'min', min(t), 'variance', max(t)-min(t)

		net_stats = {'status': 'ok', 'version': version_number, 'block_reward' : chain.m_blockchain[-1].blockheader.block_reward/100000000.00000000, 'stake_validators' : len(chain.stake_list_get()), 'epoch' : chain.m_blockchain[-1].blockheader.epoch, 'staked_percentage_emission' : staked , 'network' : 'qrl testnet', 'network_uptime': time.time()-chain.m_blockchain[1].blockheader.timestamp,'block_time' : z/len(chain.m_blockchain[-100:]), 'block_time_variance' : max(t)-min(t) ,'blockheight' : chain.m_blockheight(), 'nodes' : len(f.peers)+1, 'emission': chain.db.total_coin_supply()/100000000.000000000, 'unmined' : 21000000-chain.db.total_coin_supply()/100000000.000000000 }
		return chain.json_print_telnet(net_stats)

	def txhash(self, data=None):
		print '<<< API tx/hash call', data
		return chain.search_txhash(data)

	def address(self, data=None):
		print '<<< API address call', data
		return chain.search_address(data)

	def dataReceived(self, data=None):
		self.parse_cmd(data)
		self.transport.loseConnection()
	
	def connectionMade(self):
		self.factory.connections += 1
		#print '>>> new API connection'

	def connectionLost(self, reason):
		#print '<<< API disconnected'
		self.factory.connections -= 1


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
					#chain.json_print(chain.m_get_last_block())
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
				self.transport.write('>>> trying.. this could take up to a minute..'+'\r\n')
				print args[0], len(args[0])
				if hexseed_to_seed(args[0]) != False:
					addr = wallet.getnewaddress(type='XMSS', SEED=hexseed_to_seed(args[0]))
					self.factory.newaddress = addr
					self.transport.write('>>> Recovery address: '+ addr[1].address +'\r\n')
					self.transport.write('>>> Recovery seed phrase: '+addr[1].mnemonic + '\r\n')
					self.transport.write('>>> hexSEED confirm: '+addr[1].hexSEED+'\r\n')
					self.transport.write('>>> savenewaddress if Qaddress matches expectations..'+'\r\n')
					return

				else:
					self.transport.write('>>> Usage: recoverfromhexseed <paste in hexseed>'+'\r\n')
					self.transport.write('>>> Could take up to a minute..'+'\r\n')
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
				print 'STAKING set to: ', f.stake
				return

			elif data[0] == 'stakenextepoch':
				self.transport.write('>>> Sending a stake transaction for address: '+chain.mining_address+' to activate next epoch('+str(10000-(chain.m_blockchain[-1].blockheader.blocknumber-(chain.m_blockchain[-1].blockheader.epoch*10000)))+' blocks time)'+'\r\n')
				print 'STAKE for address:', chain.mining_address
				f.send_st_to_peers(chain.CreateStakeTransaction())
				return
			
			elif data[0] == 'send':
				self.send_tx(args)

			elif data[0] == 'mempool':
				self.transport.write('>>> Number of transactions in memory pool: '+ str(len(chain.transaction_pool))+'\r\n')

			elif data[0] == 'help':
				self.transport.write('>>> QRL ledger help: try quit, wallet, send, getnewaddress, search, recoverfromhexseed, recoverfromwords, stake, stakenextepoch, mempool, json_block, json_search, seed, hexseed, getinfo, or blockheight'+'\r\n')
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
					self.transport.write('>>> Version: '+version_number+'\r\n')
					self.transport.write('>>> Uptime: '+str(time.time()-start_time)+'\r\n')
					self.transport.write('>>> Nodes connected: '+str(len(f.peers))+'\r\n')
					self.transport.write('>>> Staking set to: '+ str(f.stake)+'\r\n')

			elif data[0] == 'blockheight':
					self.transport.write('>>> Blockheight: '+str(chain.m_blockheight())+'\r\n')
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
			print 'only one local connection allowed'
			self.transport.write('only one local connection allowed, sorry')
			self.transport.loseConnection()
		else:
			if self.transport.getPeer().host == '127.0.0.1':
				print '>>> new local connection', str(self.factory.connections), self.transport.getPeer()
				# welcome functions to run here..
			else:
				self.transport.loseConnection()
				print 'Unauthorised remote login attempt..'

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
		to_send = decimal.Decimal(decimal.Decimal(args[2])*100000000).quantize(decimal.Decimal('1'), rounding= decimal.ROUND_HALF_UP)


		if balance < to_send:
				self.transport.write('>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
				return

		(tx, msg) = chain.create_my_tx(txfrom=int(args[0]), txto=args[1], n=to_send)
		
		#self.transport.write(msg+'\r\n')
		if tx is False:
				return
		
		#print 'new local tx: ', tx
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
		pass

	def parse_msg(self, data):
		prefix = data[0:2]
		suffix = data[2:]
		
		if prefix == 'TX':				#tx received..
			#print 'ding'
			self.recv_tx(suffix)
			return
		
		if prefix == 'ST':

			try: st = chain.json_decode_st(suffix)
			except: 
				print 'st rejected - unable to decode serialised data - closing connection'
				self.transport.loseConnection()
				return

			for t in chain.stake_pool:			#duplicate tx already received, would mess up nonce..
				if st.hash == t.hash:
					return

			if chain.validate_st(st) == True:
				if chain.state_validate_st(st)==True:
					chain.add_st_to_pool(st)
				else:
					print '>>>ST',st.hash, 'invalid state validation failed..' #' invalid - closing connection to ', self.transport.getPeer().host
					return

		#if chain.state_validate_tx(tx) == True:
				print '>>>ST - ', st.hash, ' from - ', self.transport.getPeer().host, ' relaying..'
				
				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message('ST'+chain.json_bytestream(st)))
			return


		elif prefix == 'BM':	# blockheight map for synchronisation and error correction prior to POS cycle resync..
				if not suffix:
					print '<<<Sending block_map', self.transport.getPeer().host
					z = {}
					z['block_number'] = chain.m_blockchain[-1].blockheader.blocknumber
					z['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash
					self.transport.write(self.wrap_message('BM'+chain.json_encode(z)))
					return
				else:
					print '>>>Receiving block_map'
					z = chain.json_decode(suffix)
					block_number = z['block_number']
					headerhash = z['headerhash'].encode('latin1')

					i = [block_number, headerhash, self.transport.getPeer().host]
					print i
					if i not in chain.blockheight_map:
						chain.blockheight_map.append(i)
					return	

		elif prefix == 'BK':			#block received
				try: 	block = chain.json_decode_block(suffix)
				except:
						print 'block rejected - unable to decode serialised data', self.transport.getPeer().host
						return
				pre_block_logic(block)
				return

		elif prefix == 'LB':			#request for last block to be sent
				print '<<<Sending last block', str(chain.m_blockheight()), str(len(chain.json_bytestream(chain.m_get_last_block()))),' bytes', 'to node: ', self.transport.getPeer().host
				self.transport.write(self.wrap_message(chain.json_bytestream_bk(chain.m_get_last_block())))
				return

		elif prefix == 'MB':		#we send with just prefix as request..with CB number and blockhash as answer..
			if not suffix:
				print '<<<Sending blockheight to:', self.transport.getPeer().host, str(time.time())
				self.send_m_blockheight_to_peer()
				return
			
		elif prefix == 'CB':
				z = chain.json_decode(suffix)
				block_number = z['block_number']
				headerhash = z['headerhash'].encode('latin1')
				#prev_headerhash = z['prev_headerhash'].encode('latin1')

				print '>>>Blockheight from:', self.transport.getPeer().host, 'blockheight: ', block_number, 'local blockheight: ', str(chain.m_blockheight()), str(time.time())
									
				if block_number > chain.m_blockheight():		
					get_synchronising_blocks(block_number)					
					return

					# ^^ need to build this out and make it more secure..if we are successfully staking with multiple stake validators and normal block-intervals then
					# the node should be dubious of simply accepting blocks from another node..
					# something to consider is perhaps a test at the accepting block stage to compare the stake backing the new chain compared with the current chain..
					# not straightforward..


				

				if block_number == chain.m_blockheight():
						if chain.m_blockchain[block_number].blockheader.headerhash != headerhash:
							print '>>> WARNING: headerhash mismatch from ', self.transport.getPeer().host
						
						# initiate fork recovery and protection code here..
						# call an outer function which sets a flag and scrutinises the chains from all connected hosts to see what is going on..
						# again need to think this one through in detail..
						
							return


					# This is where the POS algorithm starts..

					# 1. check the block height is 0.

				if len(chain.m_blockchain) == 1 and self.factory.genesis == 0:
						self.factory.genesis = 1										# set the flag so that no other Protocol instances trigger the genesis stake functions..
						print 'genesis pos countdown to block 1 begun, 60s until stake tx circulated..'
						reactor.callLater(1, pre_pos_1)
						return
				
				elif len(chain.m_blockchain) == 1 and self.factory.genesis == 1:	#connected to multiple hosts and already passed through..
						return


				# 2. restart the network if it has paused for any reason..4 minutes restart..


				if chain.m_blockchain[-1].blockheader.timestamp < time.time()-240:
					if time.time()-f.long_gap_block < 10:
						print '240s activated already..'
						return

					f.long_gap_block = time.time()
					print 'last block was over 240s ago..resetting'
					f.send_m_blockheight_to_peers()
					reactor.callLater(5, post_block_logic)
					return


				# if we are past 1 and have matching blockheights with a random node then are we synchronised already if blocks are ?

				if block_number == chain.m_blockheight():

					if f.sync != 1:
						if f.partial_sync[0] == 1:			# if we are partially sync'd then we already came through..
								return
						

						f.partial_sync = [1, chain.m_blockheight()]		# else we activate the blockheight map and partial sync flag..
						f.get_blockheight_map_from_peers()
						post_block_logic()
						return
				

		elif prefix == 'BN':			#request for block (n)
				if int(suffix) <= chain.m_blockheight():
						print '<<<Sending block number', str(int(suffix)), str(len(chain.json_bytestream(chain.m_get_block(int(suffix))))),' bytes', 'to node: ', self.transport.getPeer().host
						self.transport.write(self.wrap_message(chain.json_bytestream_bk(chain.m_get_block(int(suffix)))))
						return
				else:
					if int(suffix) >= chain.m_blockheight():
						print 'BN for a blockheight greater than local chain length..'
						return
					else:
						print 'BN request without valid block number', suffix, '- closing connection'
						self.transport.loseConnection()
						return
		
		elif prefix == 'PO':
			if suffix[0:2] == 'NG':
				y = 0
				for entry in chain.ping_list:
					if entry['node'] == self.transport.getPeer().host:
						entry['ping (ms)'] = (time.time()-chain.last_ping)*1000
						y = 1
				if y == 0:
					chain.ping_list.append({'node': self.transport.getPeer().host, 'ping (ms)' : (time.time()-chain.last_ping)*1000})

		elif prefix == 'PI':
			if suffix[0:2] == 'NG':
				self.transport.write(self.wrap_message('PONG'))
			else:
				self.transport.loseConnection()
				return

		elif prefix == 'PL':			#receiving a list of peers to save into peer list..
				self.recv_peers(suffix)

		elif prefix == 'RT':
			'<<< Transaction_pool to peer..'
			for t in chain.transaction_pool:
				f.send_tx_to_peers(t)
			return

		elif prefix == 'PE':			#get a list of connected peers..need to add some ddos and type checking proteection here..
				self.get_peers()

		elif prefix == 'VE':
				if not suffix:
					self.transport.write(self.wrap_message('VE'+version_number))
				else:
					print self.transport.getPeer().host, 'version: ', suffix
					return

		elif prefix == 'R1':							#receive a reveal_one message sent out after block receipt or creation (could be here prior to the block!)
				z = chain.json_decode(suffix)

				block_number = z['block_number']
				headerhash = z['headerhash'].encode('latin1')
				stake_address = z['stake_address'].encode('latin1')
				reveal_one = z['reveal_one'].encode('latin1')
				reveal_two = z['reveal_two'].encode('latin1')

				for entry in chain.stake_reveal_one:	#already received, do not relay.
					if entry[3] == reveal_one:
						return

				# is reveal_one valid - does it hash to terminator in stake_list? We check that headerhash+block_number match in reveal_two_logic

				tmp = sha256(reveal_one)
				y=0
				for s in chain.stake_list_get():
					if s[0] == stake_address:
						y=1
						epoch = block_number/10000			#+1 = next block
						for x in range(block_number-(epoch*10000)):	
							tmp = sha256(tmp)
						if tmp != s[1]:
							print 'reveal doesnt hash to stake terminator', 'reveal', reveal_one, 'nonce', s[2], 'hash_term', s[1]
							return
				if y==0:
					print 'stake address not in the stake_list'
					return 


				print '>>> POS reveal_one:', self.transport.getPeer().host, stake_address, str(block_number), reveal_one

				chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one, reveal_two]) 

				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message('R1'+chain.json_encode(z)))	#relay
				return

		elif prefix == 'R2':

				z = chain.json_decode(suffix)

				block_number = z['block_number']
				headerhash = z['headerhash'].encode('latin1')
				stake_address = z['stake_address'].encode('latin1')
				reveal_one = z['reveal_one'].encode('latin1')
				nonce = z['nonce'].encode('latin1')
				winning_hash = z['winning_hash'].encode('latin1')

				for entry in chain.stake_reveal_two:	#already received, do not relay.
					if entry[4] == nonce:
						return

				# add code to accept only R2's which are at R1 level..

				# is reveal_two valid, is there an equivalent reveal_one entry for this block?

				if sha256(reveal_one+nonce) not in [s[4] for s in chain.stake_reveal_one]:
					print 'reveal_two not sha256(reveal_one+nonce) in chain.stake_reveal_one'
					return

				print '>>> POS reveal_two', self.transport.getPeer().host, stake_address, str(block_number), reveal_one

				#chain.stake_reveal_two.append([z['stake_address'],z['headerhash'], z['block_number'], z['reveal_one'], z['nonce']], z['winning_hash'])		#don't forget to store our reveal in stake_reveal_one

				chain.stake_reveal_two.append([stake_address, headerhash, block_number, reveal_one, nonce, winning_hash]) 

				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message('R2'+chain.json_encode(z)))	#relay
				return

														# could add a ttl on this..so runs around the network triggering ip calls then dissipates..or single time based bloom..

		elif prefix=='IP':								#fun feature to allow geo-tagging on qrl explorer of test nodes..reveals IP so optional..
				if not suffix:
					if self.factory.ip_geotag == 1:
						for peer in self.factory.peers:
							if peer != self:
								peer.transport.write(self.wrap_message('IP'+self.transport.getHost().host))
				else:
					if suffix not in chain.ip_list:
						chain.ip_list.append(suffix)
						for peer in self.factory.peers:
							if peer != self:
								peer.transport.write(self.wrap_message('IP'+self.transport.getHost().host))

		else:
			pass
			#print 'Data from node not understood - closing connection.'
			#self.transport.loseConnection()
		return


	def recv_peers(self, json_data):
		data = chain.json_decode(json_data)
		new_ips = []
		for ip in data:
				new_ips.append(ip.encode('latin1'))
		peers_list = chain.state_get_peers()
		print self.transport.getPeer().host, 'peers data received: ', new_ips
		for node in new_ips:
				if node not in peers_list:
					if node != self.transport.getHost().host:
						peers_list.append(node)
						reactor.connectTCP(node, 9000, f)
		chain.state_put_peers(peers_list)
		chain.state_save_peers()
		return

	def get_latest_block_from_connection(self):
		print '<<<Requested last block from', self.transport.getPeer().host
		self.transport.write(self.wrap_message('LB'))
		return

	def get_m_blockheight_from_connection(self):
		print '<<<Requesting blockheight from', self.transport.getPeer().host
		self.transport.write(self.wrap_message('MB'))
		return

	def send_m_blockheight_to_peer(self):
		z = {}
		z['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash				
		z['block_number'] = chain.m_blockchain[-1].blockheader.blocknumber 			
		self.transport.write(self.wrap_message('CB'+chain.json_encode(z)))
		return

	def get_version(self):
		print '<<<Getting version', self.transport.getPeer().host
		self.transport.write(self.wrap_message('VE'))
		return

	def get_peers(self):
		print '<<<Sending connected peers to', self.transport.getPeer().host
		peers_list = []
		for peer in self.factory.peers:
			peers_list.append(peer.transport.getPeer().host)
		self.transport.write(self.wrap_message('PL'+chain.json_encode(peers_list)))
		return

	def get_block_n(self, n):
		print '<<<Requested block: ', str(n), 'from ', self.transport.getPeer().host
		self.transport.write(self.wrap_message('BN'+str(n)))
		return

	def wrap_message(self, data):
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(data))+chr(0)+data+chr(0)+chr(0)+chr(255)

		#struct.pack('>L', len(data))

	def parse_buffer(self):
		if len(self.buffer)==0:
			return False

		d = self.buffer.find(chr(255)+chr(0)+chr(0))

		if d != -1:
			m = struct.unpack('>L', self.buffer[d+3:d+7])[0]	#get length of message
			self.buffer = self.buffer[d:]					#delete up to the start of message
		else:
			print 'Data received buffer full of garbage and deleted.'
			self.buffer = ''
			return False

		e = self.buffer.find(chr(0)+chr(0)+chr(255))

		if e == -1 and len(self.buffer) >= 8+m+3:			#we already have more than the message length with no terminator, cant trust data
			print 'Data received in buffer invalid and deleted.'
			self.buffer = ''
			return False

		if e == -1:											#no end to message in the buffer yet..
			return False

		self.messages.append(self.buffer[8:8+m])
		self.buffer = self.buffer[8+m+3:]
		return True

	def dataReceived(self, data):		# adds data received to buffer. then tries to parse the buffer twice..

		self.buffer += data

		for x in range(50):
			if self.parse_buffer()==False:
				break
			else:
				for msg in self.messages:
					#print msg
					self.parse_msg(msg)
				del self.messages[:]
		return

	def connectionMade(self):
		self.factory.connections += 1
		self.factory.peers.append(self)
		peer_list = chain.state_get_peers()
		if self.transport.getPeer().host == self.transport.getHost().host:
						if self.transport.getPeer().host in peer_list:
								print 'Self in peer_list, removing..'
								peer_list.remove(self.transport.getPeer().host)
								chain.state_put_peers(peer_list)
								chain.state_save_peers()
						self.transport.loseConnection()
						return
		
		if self.transport.getPeer().host not in peer_list:
			print 'Adding to peer_list'
			peer_list.append(self.transport.getPeer().host)
			chain.state_put_peers(peer_list)
			chain.state_save_peers()
		print '>>> new peer connection :', self.transport.getPeer().host, ' : ', str(self.transport.getPeer().port)

		self.get_m_blockheight_from_connection()
		self.get_peers()
		self.get_version()

		# here goes the code for handshake..using functions within the p2pprotocol class
		# should ask for latest block/block number.
		

	def connectionLost(self, reason):
		self.factory.connections -= 1
		print self.transport.getPeer().host,  ' disconnnected. ', 'remainder connected: ', str(self.factory.connections) #, reason 
		self.factory.peers.remove(self)
		if self.factory.connections == 0:
			stop_all_loops()
			reactor.callLater(60,f.connect_peers)

	

	def recv_tx(self, json_tx_obj):
		
		#print chain.json_decode_tx(json_tx_obj)

		try: tx = chain.json_decode_tx(json_tx_obj)
		except: 
				print 'tx rejected - unable to decode serialised data - closing connection'
				self.transport.loseConnection()
				return

		for t in chain.transaction_pool:			#duplicate tx already received, would mess up nonce..
			if tx.txhash == t.txhash:
				return

		if chain.validate_tx(tx) != True:
				print '>>>TX ', tx.txhash, 'failed validate_tx'
				return

		if chain.state_validate_tx(tx) != True:
				print '>>>TX', tx.txhash, 'failed state_validate'
				return

		print '>>>TX - ', tx.txhash, ' from - ', self.transport.getPeer().host, ' relaying..'
		chain.add_tx_to_pool(tx)

		for peer in self.factory.peers:
			if peer != self:
				peer.transport.write(self.wrap_message(chain.json_bytestream_tx(tx)))
		
		return


class p2pFactory(ServerFactory):

	protocol = p2pProtocol

	def __init__(self):
		self.stake = True			#default to mining off as the wallet functions are not that responsive at present with it enabled..
		self.peers = []
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

# factory network functions
	
	def get_block_a_to_b(self, a, b):
		print '<<<Requested blocks:', a, 'to ', b, ' from peers..'
		l = range(a,b)
		for peer in self.peers:
			if len(l) > 0:
				peer.transport.write(self.f_wrap_message('BN'+str(l.pop(0))))
			else:
				return				

	def get_block_n_random_peer(self,n):
		print '<<<Requested block: ', n, 'from random peer.'
		random.choice(self.peers).get_block_n(n)
		return


	def get_block_n(self, n):
		print '<<<Requested block: ', n, 'from peers.'
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('BN'+str(n)))
		return

	def get_m_blockheight_from_random_peer(self):
		print '<<<Requested blockheight from random peer.'
		random.choice(self.peers).get_m_blockheight_from_connection()
		return

	def get_blockheight_map_from_peers(self):
		print '<<<Requested blockheight_map from peers.'
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('BM'))
		return

	def get_m_blockheight_from_peers(self):
		for peer in self.peers:
			peer.get_m_blockheight_from_connection()
		return

	def send_m_blockheight_to_peers(self):
		print '<<<Sending blockheight to peers.'
		for peer in self.peers:
			peer.send_m_blockheight_to_peer()
		return

	def f_wrap_message(self, data):
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(data))+chr(0)+data+chr(0)+chr(0)+chr(255)

	def send_st_to_peers(self, st):
		print '<<<Transmitting ST:', st.hash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('ST'+chain.json_bytestream(st)))
		return

	def send_tx_to_peers(self, tx):
		print '<<<Transmitting TX: ', tx.txhash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message(chain.json_bytestream_tx(tx)))
		return


	# transmit reveal_one hash..

	def send_stake_reveal_one(self):
		
		print '<<<Transmitting POS reveal_one'
		z = {}
		z['stake_address'] = chain.mining_address
		z['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash				#demonstrate the hash from last block to prevent building upon invalid block..
		z['block_number'] = chain.m_blockchain[-1].blockheader.blocknumber+1		#next block..
		epoch = z['block_number']/10000			#+1 = next block
		z['reveal_one'] = chain.hash_chain[:-1][::-1][z['block_number']-(epoch*10000)]	
		rkey = random_key()
		z['reveal_two'] = sha256(z['reveal_one']+rkey)
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('R1'+chain.json_encode(z)))
		
		chain.stake_reveal_one.append([z['stake_address'],z['headerhash'], z['block_number'], z['reveal_one'], z['reveal_two'], rkey])		#don't forget to store our reveal in stake_reveal_one
		return


	# transmit reveal_two hash..

	def send_stake_reveal_two(self, winning_hash):
		
		print '<<<Transmitting POS reveal_two'
		z = {}
		z['stake_address'] = chain.mining_address
		z['headerhash'] = chain.m_blockchain[-1].blockheader.headerhash				#demonstrate the hash from last block to prevent building upon invalid block..
		z['block_number'] = chain.m_blockchain[-1].blockheader.blocknumber+1		#next block..
		epoch = z['block_number']/10000			#+1 = next block
		z['reveal_one'] = chain.hash_chain[:-1][::-1][z['block_number']-(epoch*10000)]	
		for s in chain.stake_reveal_one:
			if len(s)==6:
				if s[3]==z['reveal_one']:			#consider adding checks here..
					rkey = s[5]
		z['nonce'] = rkey
		z['winning_hash'] = winning_hash

		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('R2'+chain.json_encode(z)))
		
		chain.stake_reveal_two.append([z['stake_address'],z['headerhash'], z['block_number'], z['reveal_one'], z['nonce'], z['winning_hash']])		#don't forget to store our reveal in stake_reveal_one
		return


	def ip_geotag_peers(self):
		print '<<<IP geotag broadcast'
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('IP'))
		return


	def ping_peers(self):
		print '<<<Transmitting network PING'
		chain.last_ping = time.time()
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('PING'))
		return

	# send POS block to peers..

	def send_stake_block(self, block_obj):
		print '<<<Transmitting POS created block', str(block_obj.blockheader.blocknumber), block_obj.blockheader.headerhash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('S4'+chain.json_byestream(block_obj)))
		return

	# send/relay block to peers

	def send_block_to_peers(self, block):
		print '<<<Transmitting block: ', block.blockheader.headerhash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message(chain.json_bytestream_bk(block)))
		return

	# request transaction_pool from peers

	def get_tx_pool_from_peers(self):
		print '<<<Requesting TX pool from peers..'
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('RT'))
		return

# connection functions

	def connect_peers(self):
		print '<<<Reconnecting to peer list:'
		for peer in chain.state_get_peers():
			reactor.connectTCP(peer, 9000, f)

	def clientConnectionLost(self, connector, reason):		#try and reconnect
		#print 'connection lost: ', reason, 'trying reconnect'
		#connector.connect()
		return

	def clientConnectionFailed(self, connector, reason):
		#print 'connection failed: ', reason
		return

	def startedConnecting(self, connector):
		#print 'Started to connect.', connector
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
	print 'Reading chain..'
	chain.m_load_chain()
	print str(len(chain.m_blockchain))+' blocks'
	print 'Verifying chain'
	#chain.state_add_block(m_blockchain[1])
	#chain.m_verify_chain(verbose=1)
	print 'Building state leveldb'
	#chain.state_read_chain()
	chain.verify_chain()
	print 'Loading node list..'			# load the peers for connection based upon previous history..
	chain.state_load_peers()
	print chain.state_get_peers()

	stuff = 'QRL node connection established. Try starting with "help"'+'\r\n'
	print '>>>Listening..'
	
	f = p2pFactory()
	api = ApiFactory()

	reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
	reactor.listenTCP(9000, f)
	reactor.listenTCP(8080, api)


	print 'Connect to the node via telnet session on port 2000: i.e "telnet localhost 2000"'
	print '<<<Connecting to nodes in peer.dat'

	f.connect_peers()
	reactor.run()
	    