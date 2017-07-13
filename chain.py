#QRL main blockchain, state, stake, transaction functions.

# todo:
# pos_block_pool() should return all combinations, not just the order received then sorted by txhash - removes edge cases for block selection failure..
# add stake list check to the state check - addresses which are staking cannot make transactions..
# block-reward calculation to be altered based upon block-time and stake_list_get() balances..proportion of entire coin supply..
# fees
# occasionally the ots index gets behind..find reason..
# add salt/key xor to hash chains..

__author__ = 'pete'

import ntp
import configuration as c
from merkle import sha256, numlist
from StringIO import StringIO
from time import time, sleep
from operator import itemgetter, attrgetter
from math import log, ceil
import heapq

import os, copy, ast, sys, jsonpickle, decimal
import simplejson as json
from collections import defaultdict
import merkle, wallet, db

import cPickle as pickle

global transaction_pool, stake_pool, txhash_timestamp, m_blockchain, my, node_list, ping_list, last_ping, recent_blocks, pos_d, pos_flag, ip_list, blockheight_map, pos_consensus

global mining_address, stake_list, stake_commit, stake_reveal, hash_chain, epoch_prf, epoch_PRF, tx_per_block, stake_reveal_one, stake_reveal_two, stake_reveal_three, expected_winner

version_number = "alpha/0.09a"
reorg_limit = 10
minimum_required_stakers = 3
hashchain_nums = 51	#1 Primary and 50 Secondary hashchain
merkle.hashchain_nums = hashchain_nums	# Set value to merkle module
tx_per_block = [0, 0]
ping_list = []
node_list = ['104.251.219.184']
m_blockchain = []
block_chain_buffer = None	#Initialized by node.py
transaction_pool = []
prev_txpool = [None]*1000
pending_tx_pool = []
pending_tx_pool_hash = []
txhash_timestamp = []
stake_commit = []
stake_reveal = []
stake_reveal_one = []
stake_reveal_two = []
stake_reveal_three = []
last_stake_reveal_one = []
stake_ban_list = []
stake_ban_block = {}
stake_pool = []
stake_list = []
epoch_prf = []
epoch_PRF = []
expected_winner = []
recent_blocks = []
pos_d = []
pos_consensus = []
pos_flag = []
ip_list = []
blockheight_map = []
stake_validator_latency = defaultdict(dict)
ntp.setOffset()	# Set Time Offset

printL(( 'QRL blockchain ledger v', version_number))
printL(( 'loading db'))
db = db.DB()

printL(( 'loading wallet'))
my = wallet.f_read_wallet()
wallet.f_load_winfo()
mining_address = my[0][1].address
printL(( 'mining/staking address', mining_address))
#hash_chain = my[0][1].hc

# pos

def validate_block_timestamp(timestamp, blocknumber):
	last_block_timestamp = m_blockchain[-1].blockheader.timestamp
	if last_block_timestamp>=timestamp:
		return False
	curr_time = ntp.getTime()
	if curr_time == 0:
		return False
	block_creation_second = 55
	
	max_block_number = int((curr_time - last_block_timestamp)/block_creation_second)
	if blocknumber > max_block_number:
		return False

def validate_reboot(hash, nonce):
	reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]
	try:
		reboot_data = db.get('reboot_data')
	except:
		pass
	if reboot_data[1]>nonce:	#already used
		return 
	reboot_data[1] = nonce
	output = hash
	for i in range(0, reboot_data[1]):
		output = sha256(output)

	if output != hash:
		return False
	reboot_data[1] += 1
	db.put('reboot_data', reboot_data)
	return True

def generate_reboot_hash(key, nonce=None):		
	reboot_data = ['2920c8ec34f04f59b7df4284a4b41ca8cbec82ccdde331dd2d64cc89156af653', 0]
	try:
		reboot_data = db.get('reboot_data')
	except:
		pass
	if nonce:
		if reboot_data[1]>nonce:
			return None, 'Nonce must be greater than or equals to '+str(reboot_data[1])+'\r\n'
		reboot_data[1] = nonce
	
	output = sha256(key)
	for i in range(0, 40000-reboot_data[1]):
		output = sha256(output)

	if not validate_reboot(output, reboot_data[1]):
		return None, 'Invalid Key\r\n'

	return json.dumps({'hash':output, 'nonce':reboot_data[1]}), "Reboot Initiated\r\n"

def get_sv(terminator):
	for s in stake_list_get():
		if terminator in s[1]:
			return s[0]

	return None

def reveal_to_terminator(reveal, blocknumber):
	tmp = sha256(reveal)
	epoch = blocknumber/c.blocks_per_epoch
	for x in range(blocknumber-(epoch*c.blocks_per_epoch)):
		tmp = sha256(tmp)
	return tmp

def select_hashchain(last_block_headerhash, stake_address=None, hashchain=None, blocknumber=None):

	if not hashchain:
		for s in block_chain_buffer.stake_list_get(blocknumber):
			if s[0] == stake_address:
				hashchain = s[1]
				break

	if not hashchain:
		return

	target_chain = 0
	for byte in last_block_headerhash:
		target_chain += ord(byte)

	target_chain = (target_chain - 1) % (hashchain_nums - 1)	# 1 Primary hashchain size

	return hashchain[-1], hashchain[target_chain]

def select_winners(reveals, topN=1, blocknumber=None, block=None):
	#chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one, score])
	winners = None
	#curframe = inspect.currentframe()
	#calframe = inspect.getouterframes(curframe, 2)
	if blocknumber:
		winners = heapq.nsmallest(topN, reveals, key=lambda reveal: score(get_sv(reveal_to_terminator(reveal, blocknumber)), reveal, blocknumber=blocknumber, block=block) )
		return winners

	winners = heapq.nsmallest(topN, reveals, key=lambda reveal: reveal[4]) #reveal[4] is score
	winners_dict = {}
	for winner in winners:
		winners_dict[winner[3]] = winner # winner[3] is reveal_one
	return winners_dict

def score(stake_address, reveal_one, block_reward = 0, blocknumber = None, block = None):
	balance = state_balance(stake_address)
	if balance == 0.0:
		printL (( ' balance 0 so score none ' ))
		return None

	epoch = blocknumber/c.blocks_per_epoch
	epoch_PRF = None

	epoch_PRF = block_chain_buffer.get_epoch_PRF(blocknumber, block)

	PRF = int(epoch_PRF[blocknumber-(epoch*c.blocks_per_epoch)], 16)
	reveal_one_number = int(reveal_one, 16)
	score = abs(PRF-reveal_one_number)*1.0/(balance+block_reward)
	return score

def update_pending_tx_pool(tx, peer):
	if len(pending_tx_pool)>=c.blocks_per_epoch:
		del pending_tx_pool[0]
		del pending_tx_pool_hash[0]
	pending_tx_pool.append([tx, peer])
	pending_tx_pool_hash.append(tx.txhash)

def get_stake_validators_hash():
	sv_hash = StringIO()
	stakers = stake_list_get()
	for staker in stakers:
		balance = state_balance(staker[0])
		sv_hash.write(staker[0]+str(balance))
	sv_hash = sha256(sv_hash.getvalue())
	return sv_hash
	
# create a block from a list of supplied tx_hashes, check state to ensure validity..

def create_stake_block(tx_hash_list, hashchain_hash, reveal_list, last_block_number):

	# full memory copy of the transaction pool..

	global transaction_pool

	t_pool2 = copy.deepcopy(transaction_pool)

	del transaction_pool[:]

	# recreate the transaction pool as in the tx_hash_list, ordered by txhash..

	d = []

	for tx in tx_hash_list:
		for t in t_pool2:
			if tx == t.txhash:
				d.append(t.txfrom)
				transaction_pool.append(t)
				t.nonce = state_nonce(t.txfrom)+d.count(t.txfrom)

	# create the block..

	block_obj = m_create_block(hashchain_hash, reveal_list, last_block_number)

	# reset the pool back

	transaction_pool = copy.deepcopy(t_pool2)

	return block_obj

# return a sorted list of txhashes from transaction_pool, sorted by timestamp from block n (actually from start of transaction_pool) to time, then ordered by txhash.

def sorted_tx_pool(timestamp=None):
	if timestamp == None:
		timestamp=time()
	pool = copy.deepcopy(transaction_pool)
	trimmed_pool = []
	end_time = timestamp
	for tx in pool:
		#if txhash_timestamp[txhash_timestamp.index(tx.txhash)+1] >= start_time and txhash_timestamp[txhash_timestamp.index(tx.txhash)+1] <= end_time:
		if txhash_timestamp[txhash_timestamp.index(tx.txhash)+1] <= end_time:
					trimmed_pool.append(tx.txhash)

	trimmed_pool.sort()

	if trimmed_pool == []:
		return False

	return trimmed_pool

# merkle tree root hash of tx from pool for next POS block

def merkle_tx_hash(hashes):
	#printL(( 'type', type(hashes), 'len', len(hashes)
	if len(hashes)==64:					# if len = 64 then it is a single hash string rather than a list..
		return hashes
	j=int(ceil(log(len(hashes),2)))
	l_array = []
	l_array.append(hashes)
	for x in range(j):
		next_layer = []
		i = len(l_array[x])%2 + len(l_array[x])/2
		z=0
		for y in range(i):
			if len(l_array[x])==z+1:
				next_layer.append(l_array[x][z])
			else:
				next_layer.append(sha256(l_array[x][z]+l_array[x][z+1]))
			z+=2
		l_array.append(next_layer)
	#printL(( l_array
	return ''.join(l_array[-1])

# return closest hash in numerical terms to merkle root hash of all the supplied hashes..

def closest_hash(list_hash):
	#printL(( 'list_hash', list_hash, len(list_hash)

	if type(list_hash) == list:
		if len(list_hash)==1:
			return False, False
	if type(list_hash)== str:
		if len(list_hash)==64:
			return False, False

	list_hash.sort()

	root = merkle_tx_hash(list_hash)

	p = []
	for l in list_hash:
		p.append(int(l,16))

	closest = cl(int(root,16),p)

	return ''.join(list_hash[p.index(closest)]), root


# return closest number in a hexlified list

def cl_hex(one, many):

	p = []
	for l in many:
		p.append(int(l,16))

	return many[p.index(cl(int(one,16), p))]


# return closest number in a list..

def cl(one, many):
	return min(many, key=lambda x:abs(x-one))


def is_stake_banned(stake_address):
	if stake_address in stake_ban_list:
		epoch_diff = (m_blockheight()/c.blocks_per_epoch) - (stake_ban_block[stake_address]/c.blocks_per_epoch)
		if m_blockheight() - stake_ban_block[stake_address] > 10 or epoch_diff > 0:
			printL (( 'Stake removed from ban list' ))
			del stake_ban_block[stake_address]
			stake_ban_list.remove(stake_address)
			return False
		return True
		
	return False
			
def ban_stake(stake_address):
	printL (('stake address ', stake_address, ' added to block list' ))
	stake_ban_list.append(stake_address)
	stake_ban_block[stake_address] = m_blockheight()+1


# create a snapshot of the transaction pool to account for network traversal time (probably less than 300ms, but let's give a window of 1.5 seconds). 
# returns: list of merkle root hashes of the tx pool over last 1.5 seconds

#import itertools
# itertools.permutations([1, 2, 3])

def pos_block_pool(n=1.5):
	timestamp = time()
	start_time = timestamp-n

	x = sorted_tx_pool(start_time)
	y = sorted_tx_pool(timestamp)
	if y == False:				# if pool is empty -> return sha256 null
		return [sha256('')], [[]]
	elif x == y:					# if the pool isnt empty but there is no difference then return the only merkle hash possible..
		return [merkle_tx_hash(y)], [y]
	else:						# there is a difference in contents of pool over last 1.5 seconds..
		merkle_hashes = []
		txhashes = []
		if x == False:				
			merkle_hashes.append(sha256(''))
			x = []
			txhashes.append(x)
		else:
			merkle_hashes.append(merkle_tx_hash(x))
			txhashes.append(x)
		tmp_txhashes = x

		for tx in reversed(transaction_pool):
			if tx.txhash in y and tx.txhash not in x:
				tmp_txhashes.append(tx.txhash)
				tmp_txhashes.sort()
				merkle_hashes.append(merkle_tx_hash(tmp_txhashes))
				txhashes.append(tmp_txhashes)

		return merkle_hashes, txhashes	

# create the PRF selector sequence based upon a seed and number of stakers in list (temporary..there are better ways to do this with bigger seed value, but it works)

def pos_block_selector(seed, n):
	n_bits = int(ceil(log(n,2)))
	prf = merkle.GEN_range_bin(seed, 1, 20000,1)
	prf_range = []
	for z in prf:
		x = ord(z) >> 8-n_bits
		if x < n:
			prf_range.append(x)
	return prf_range

# return the POS staker list position for given seed at index, i

def pos_block_selector_n(seed, n, i):
	l = pos_block_selector(seed, n)
	return l[i]

class BlockBuffer:
	def __init__(self, block, stake_reward):
		self.block = block
		self.stake_reward = stake_reward
		self.score = self.block_score()

	def block_score(self):
		reward = 0
		stake_selector = self.block.blockheader.stake_selector
		if stake_selector in self.stake_reward:
			reward = self.stake_reward[stake_selector]

		score_val = score(self.block.blockheader.stake_selector, self.block.blockheader.hash, reward, self.block.blockheader.blocknumber)
		return score_val

class ChainBuffer:
	def __init__(self, size=3):
		self.blocks = {}
		self.headerhashes = {}
		self.size = size
		self.pending_blocks = {}
		self.epoch = int(max(0,height())/c.blocks_per_epoch)	#Main chain epoch
		self.stake_list = {}
		self.stake_list[self.epoch] = stake_list_get()	#stake list buffer
		self.next_stake_list = {}
		self.next_stake_list[self.epoch] = next_stake_list_get()
		self.epoch_PRF = {}
		self.update_epoch_PRF(self.epoch*c.blocks_per_epoch)
		self.hash_chain = {}
		self.hash_chain[self.epoch] = my[0][1].hc
		self.tx_buffer = []	# maintain the list of tx transaction that has been confirmed in buffer
		self.st_buffer = []	# maintain the list of st transaction that has been confirmed in buffer
		if len(m_blockchain)>0:
			self.epoch = int(m_blockchain[-1].blockheader.blocknumber/c.blocks_per_epoch)

	def add_pending_block(self, block):
		#TODO : minimum block validation in unsynced state

		blocknum = block.blockheader.blocknumber
		headerhash = block.blockheader.headerhash
		prev_headerhash = block.blockheader.prev_blockheaderhash

		if blocknum not in self.pending_blocks:
			self.pending_blocks[blocknum] = []

		if headerhash in self.pending_blocks[blocknum]:
			return

		self.pending_blocks[blocknum].append(block)

		return True

	def get_last_block(self):
		if len(self.blocks) == 0:
			return m_get_last_block()

		blocknum = height() + 1
		last_block = m_blockchain[-1]
		prev_headerhash = m_blockchain[-1].blockheader.headerhash
		block = self.get_strongest_block(blocknum, prev_headerhash)
		while block != None:
			last_block = block
			prev_headerhash = block.blockheader.headerhash
			blocknum += 1
			block = self.get_strongest_block(blocknum, prev_headerhash)

		return last_block

	def get_block_n(self, blocknum):
		if len(m_blockchain) == 0:
			m_read_chain()

		if blocknum < len(m_blockchain):
			return m_blockchain[blocknum]

		if blocknum not in self.blocks:
			return None

		target_blocknum = blocknum
		blocknum = height() + 1
		prev_headerhash = m_blockchain[-1].blockheader.headerhash
		block = self.get_strongest_block(blocknum, prev_headerhash)

		while block != None:
			if blocknum == target_blocknum:
				break
			prev_headerhash = block.blockheader.headerhash
			blocknum += 1
			block = self.get_strongest_block(blocknum, prev_headerhash)

		return block

	def stake_list_get(self, blocknum):
		epoch = int(blocknum/c.blocks_per_epoch)
		if blocknum < len(m_blockchain):
			self.stake_list[epoch] = stake_list_get()
			self.next_stake_list[epoch - 1] = stake_list_get()
			return self.stake_list[epoch]
		
		if epoch not in self.stake_list and epoch == self.epoch + 1:
			self.stake_list[epoch] = self.next_stake_list[epoch-1] #next_stake_list_get()
		if len(self.stake_list[epoch]) == 0 and epoch == self.epoch:
			self.stake_list[epoch] = stake_list_get()

		return self.stake_list[epoch]

	def next_stake_list_get(self, blocknum):
		if blocknum < len(m_blockchain):
			return next_stake_list_get()

		epoch = int(blocknum/c.blocks_per_epoch)
		if epoch not in self.next_stake_list and epoch == self.epoch + 1:
			self.next_stake_list[epoch] = []
		return self.next_stake_list[epoch]

	def update_next_stake_list(self):
		epoch = int(height()/c.blocks_per_epoch)
		self.next_stake_list[epoch] = next_stake_list_get()

		prev_headerhash = m_blockchain[-1].blockheader.headerhash

		for blocknum in range(height() + 1, self.height() + 1):
			epoch = int(blocknum/c.blocks_per_epoch)
			if epoch not in self.next_stake_list:
				self.next_stake_list[epoch] = []
			tmp_block = self.get_strongest_block(blocknum, prev_headerhash)
			if tmp_block == None:
				return
			prev_headerhash = tmp_block.blockheader.headerhash
			if blocknum == 1:
				continue
			for st in tmp_block.stake:
				found = False
				for st2 in self.next_stake_list[epoch]:
					if st.txfrom == st2[0]:
						found = True
						st2[1] = st.hash
						break
				if not found:
					self.next_stake_list[epoch].append([st.txfrom, st.hash, 0])

	def update_stake_list(self, block):
		block_left = c.blocks_per_epoch - (block.blockheader.blocknumber - (block.blockheader.epoch*c.blocks_per_epoch))
		epoch = int((block.blockheader.blocknumber+1)/c.blocks_per_epoch)
		if block.blockheader.blocknumber != 1 and block_left != 1:
			return
		if epoch not in self.stake_list:
			self.stake_list[epoch] = []
			self.next_stake_list[epoch] = []
		if block.blockheader.blocknumber == 1:
			for st in block.stake:
				if st.txfrom == block.blockheader.stake_selector:
					if st.txfrom in m_blockchain[0].stake_list:
						self.stake_list[0].append([st.txfrom, st.hash, 1])
					else:
						printL(( 'designated staker not in genesis..'))
				else:
					if st.txfrom in m_blockchain[0].stake_list:
						self.stake_list[0].append([st.txfrom, st.hash, 0])
					else:
						self.next_stake_list[0].append([st.txfrom, st.hash, 0])
		else:
			self.stake_list[epoch] = self.next_stake_list_get( (epoch*c.blocks_per_epoch) - 1 )
			self.next_stake_list[epoch] = []

	def get_epoch_PRF(self, blocknumber, block=None):
		epoch = int(blocknumber/c.blocks_per_epoch)
		if epoch not in self.epoch_PRF:
			self.update_epoch_PRF(blocknumber, block)
		return self.epoch_PRF[epoch]

	def update_epoch_PRF(self, blocknumber, block=None):
		epoch = int((blocknumber+1)/c.blocks_per_epoch)
		if epoch == 0:
			self.epoch_PRF[epoch] = merkle.GEN_range(m_blockchain[epoch*c.blocks_per_epoch].stake_seed, 1, c.blocks_per_epoch, 32)
			return

		block_3_headerhash = self.get_block_n(blocknumber-3).blockheader.headerhash
		block_2_headerhash = self.get_block_n(blocknumber-2).blockheader.headerhash
		block_1_headerhash = self.get_block_n(blocknumber-1).blockheader.headerhash
		if not block:
			block = self.get_block_n(blocknumber)
		block_0_headerhash = block.blockheader.headerhash

		entropy = block_3_headerhash+block_2_headerhash+block_1_headerhash+block_0_headerhash
		self.epoch_PRF[epoch] = merkle.GEN_range(m_blockchain[0].stake_seed+entropy, 1, c.blocks_per_epoch, 32)

	def hash_chain_get(self, blocknumber):
		epoch = int(blocknumber/c.blocks_per_epoch)
		return self.hash_chain[epoch]

	def update_hash_chain(self, blocknumber):
		epoch = int((blocknumber+1)/c.blocks_per_epoch)
		printL (( 'Created new hash chain' ))
		my[0][1].hashchain(epoch=epoch)
		self.hash_chain[epoch] = my[0][1].hc
		wallet.f_save_wallet()

	def add_txns_buffer(self):
		if len(self.blocks) == 0:
			return
		self.tx_buffer = []
		self.st_buffer = []
		min_blocknum = height()+1
		min_epoch = int(min_blocknum/c.blocks_per_epoch)
		max_blocknum = max(self.blocks.keys())
		max_epoch = int(max_blocknum/c.blocks_per_epoch)
		prev_headerhash = m_blockchain[min_blocknum-1].blockheader.headerhash
		for blocknum in range(min_blocknum, max_blocknum+1):
			block = self.get_strongest_block(blocknum, prev_headerhash)
			prev_headerhash = block.blockheader.headerhash

			for st in block.stake:
				self.st_buffer.append(st.hash) #Assuming stake transactions are valid

			for tx in block.transactions:
				self.tx_buffer.append(tx.txhash)
				
	def add_block_mainchain(self, block, verify_block_reveal_list=True, validate=True):

		#TODO : minimum block validation in unsynced state
		blocknum = block.blockheader.blocknumber
		epoch = int(blocknum/c.blocks_per_epoch)
		headerhash = block.blockheader.headerhash
		prev_headerhash = block.blockheader.prev_blockheaderhash

		if blocknum <= height():
			return

		if len(self.blocks) == 0:
			if prev_headerhash != m_blockchain[-1].blockheader.headerhash:
				return
		elif len(self.blocks) > 0:
			if blocknum - 1 not in self.blocks or prev_headerhash not in self.headerhashes[blocknum-1]:
				return
		
		if validate:
			if not m_add_block(block, verify_block_reveal_list):
				printL (( "Failed to add block by m_add_block, re-requesting the block #", blocknum ))
				return 
		else:
			if state_add_block(block) is True:
				m_blockchain.append(block)

		block_left = c.blocks_per_epoch - (block.blockheader.blocknumber - (block.blockheader.epoch*c.blocks_per_epoch))

		self.add_txns_buffer()
		if block.blockheader.blocknumber == 1:
			self.stake_list[epoch] = stake_list_get()
		if block_left == 1:	#As state_add_block would have already moved the next stake list to stake_list
			self.stake_list[epoch+1] = stake_list_get()
			self.next_stake_list[epoch+1] = next_stake_list_get()
			self.update_epoch_PRF(block.blockheader.blocknumber)
			self.update_hash_chain(block.blockheader.blocknumber)
		self.next_stake_list[epoch] = next_stake_list_get()
		self.epoch = epoch
		return True

	def add_block(self, block):
		#TODO : minimum block validation in unsynced state
		blocknum = block.blockheader.blocknumber
		headerhash = block.blockheader.headerhash
		prev_headerhash = block.blockheader.prev_blockheaderhash

		if blocknum <= height():
			return True

		if blocknum - 1 == height():
			if prev_headerhash != m_blockchain[-1].blockheader.headerhash:
				printL (( 'Failed due to prevheaderhash mismatch, blockslen ', len(self.blocks) ))
				return
		else:
			if blocknum - 1 not in self.blocks or prev_headerhash not in self.headerhashes[blocknum-1]:
				printL (( 'Failed due to prevheaderhash mismatch, blockslen ', len(self.blocks) ))
				return
		
		if blocknum not in self.blocks:
			self.blocks[blocknum] = []
			self.headerhashes[blocknum] = []

		if headerhash in self.headerhashes[blocknum]:
			return 0

		if min(self.blocks)+self.size <= blocknum:
			self.move_to_mainchain()

		stake_reward = {}
		if len(self.blocks) > 0 and (blocknum - 1) in self.blocks:
			for blockBuffer in self.blocks[blocknum-1]:
				if blockBuffer.block.blockheader.headerhash == prev_headerhash:
					stake_reward = dict(blockBuffer.stake_reward)
					prev_stake_selector = blockBuffer.block.blockheader.stake_selector
					if prev_stake_selector not in stake_reward:
						stake_reward[prev_stake_selector] = 0
					stake_reward[prev_stake_selector] += blockBuffer.block.blockheader.block_reward
					break

		self.blocks[blocknum].append(BlockBuffer(block, stake_reward))
		self.blocks[blocknum] = sorted(self.blocks[blocknum], key=attrgetter('score'))

		self.headerhashes[blocknum].append(block.blockheader.headerhash)

		block_left = c.blocks_per_epoch - (block.blockheader.blocknumber - (block.blockheader.epoch*c.blocks_per_epoch))

		#if block.blockheader.headerhash == self.blocks[blocknum][0].block.blockheader.headerhash:
		if self.get_last_block().blockheader.headerhash == block.blockheader.headerhash:
			self.add_txns_buffer()
			if block_left == 1 or block.blockheader.blocknumber == 1:
				self.update_stake_list(block)
			if block_left == 1:
				self.update_epoch_PRF(block.blockheader.blocknumber)
				self.update_hash_chain(block.blockheader.blocknumber)
			self.update_nonce()
			self.update_next_stake_list()
			#self.update_score()


		return True

	def update_score(self):
		blocknum = blocknum
		prev_headerhash = m_blockchain[-1].blockheader.headerhash

		for blockBuffer in self.blocks[blocknum]:
			if prev_headerhash == blockBuffer.block.blockheader.prev_blockheaderhash:
				return blockBuffer.block

		return None

	def update_nonce(self):
		max_blocknum = self.height()
		#epoch = int(max_blocknum/c.blocks_per_epoch)
		#min_blocknum = epoch*c.blocks_per_epoch
		#if epoch  == self.epoch:
		#	min_blocknum = min(self.blocks)
		min_blocknum = min(self.blocks)
		min_epoch = int(min_blocknum/c.blocks_per_epoch)
		max_epoch = int(max_blocknum/c.blocks_per_epoch)

		prev_headerhash =  m_blockchain[-1].blockheader.headerhash
		for epoch in range(min_epoch, max_epoch+1):
			for staker in self.stake_list[epoch]:
				staker[2] = 0

		for staker in stake_list_get():
			for staker2 in self.stake_list[min_epoch]:
				if staker[0] == staker2[0]:
					staker2[2] = staker[2]
		
		for blocknum in range(min_blocknum, max_blocknum + 1):
			block = self.get_strongest_block(blocknum, prev_headerhash)
			if block == None:
				return
			prev_headerhash = block.blockheader.headerhash
			epoch = int(blocknum/c.blocks_per_epoch)
			if block.blockheader.blocknumber < min_blocknum:
				continue
			for staker in self.stake_list[epoch]:
				if staker[0] == block.blockheader.stake_selector:
					staker[2] += 1

	def describe(self):
		min_block = min(self.blocks)
		max_block = max(self.blocks)
		printL (( '='*40 ))
		for blocknum in range(min_block,max_block+1):
			printL (( 'Block number #', str(blocknum) ))
			for blockBuffer in self.blocks[blocknum]:
				block = blockBuffer.block
				printL (( block.blockheader.headerhash, ' ', str(blockBuffer.score), ' ', str(block.blockheader.block_reward) ))
				printL (( block.blockheader.hash, ' ', block.blockheader.stake_selector )) 
		printL (( '='*40 ))


	def move_to_mainchain(self):
		printL (( 'Transaction pool size ', len(transaction_pool) ))
		printL (( 'Tx Buffer ', len(self.tx_buffer) ))
		for txn in transaction_pool:
			printL (( 'Transaction ', txn.txhash, 'From ', txn.txfrom))
		for txn in self.tx_buffer:
			printL (( 'buffer tx hash ', txn))
		blocknum = height() + 1

		block = self.get_strongest_block(blocknum, m_blockchain[-1].blockheader.headerhash)
		if not state_add_block(block):
			printL (( 'last block failed state/stake checks, removed from chain' ))
			return False

		m_blockchain.append(block)
		remove_tx_in_block_from_pool(block) #modify fn to keep transaction in memory till reorg
		remove_st_in_block_from_pool(block) #modify fn to keep transaction in memory till reorg
		m_f_sync_chain()
		del(self.blocks[blocknum])
		del(self.headerhashes[blocknum])
		prev_epoch = self.epoch
		self.epoch = int(blocknum/c.blocks_per_epoch)
		if prev_epoch != self.epoch:
			del self.next_stake_list[prev_epoch]
			del self.stake_list[prev_epoch]
			del self.hash_chain[prev_epoch]
		return True

	def height(self):
		blocknum = height() + 1
		prev_headerhash = m_blockchain[-1].blockheader.headerhash
		block = self.get_strongest_block(blocknum, prev_headerhash)
		while block != None:
			prev_headerhash = block.blockheader.headerhash
			blocknum += 1
			block = self.get_strongest_block(blocknum, prev_headerhash)

		return blocknum - 1
		#return len(self.blocks) + len(m_blockchain) - 1

	def get_strongest_block(self, blocknum, prev_headerhash):
		blocknum = blocknum
		if blocknum not in self.blocks:
			return None
		for blockBuffer in self.blocks[blocknum]:
			if prev_headerhash == blockBuffer.block.blockheader.prev_blockheaderhash:
				return blockBuffer.block

		return None
		#return self.blocks[blocknum][0].block

	def get_strongest_headerhash(self, blocknum):
		if blocknum < len(m_blockchain):
			return m_blockchain[blocknum].blockheader.headerhash
		if blocknum not in self.blocks:
			printL (( 'Blocknum : ', str(blocknum), ' not found in buffer' ))
			return None
		max_blocknum = max(self.blocks)
		min_blocknum = height() + 1
		prev_headerhash = m_blockchain[-1].blockheader.headerhash
		for blocknum in range(min_blocknum, max_blocknum + 1):
			block = self.get_strongest_block(blocknum, prev_headerhash)
			prev_headerhash = block.blockheader.headerhash

		return prev_headerhash
		
	def send_block(self, blocknumber, transport, wrap_message):
		if blocknumber < len(m_blockchain):
			transport.write( wrap_message('PB', json_bytestream(m_get_block(blocknumber))) )
		elif blocknumber in self.blocks:
			tmp = {blocknumber:[]}
			for blockBuffer in self.blocks[blocknumber]:
				tmp[blocknumber].append(blockBuffer.block)
			transport.write( wrap_message('PBB', json_encode_complex(tmp) ) )

	def process_pending_blocks(self):
		min_blocknum = min(self.pending_blocks.keys())
		max_blocknum = max(self.pending_blocks.keys())
		for blocknum in range(min_blocknum, max_blocknum + 1):
			for block in self.pending_blocks[blocknum]:
				self.add_block(block)
			del self.pending_blocks[blocknum]
		

#A base class to be inherited by all other transaction
class Transaction():
	def __init__(self):
		pass

	def process_XMSS(self, type, txfrom, txhash):
		self.txfrom = txfrom.encode('ascii')
		self.txhash = txhash
		#for hashnum in range(len(txhash)):
		#	self.txhash[hashnum] = self.txhash[hashnum].encode('ascii')
		data = my[0][1]
		S = data.SIGN(str(self.txhash))				# Sig = {i, s, auth_route, i_bms, self.pk(i), self.PK_short}
		self.i = S[0]
		self.signature = S[1]
		self.merkle_path = S[2]
		self.i_bms = S[3]
		self.pub = S[4]
		self.PK = S[5]
		self.type = type
	
	def json_to_transaction(self, json_str_tx):
		self.dict_to_transaction(json.loads(json_str_tx))
		return self

	def dict_to_transaction(self, dict_tx):
		self.__dict__ = dict_tx
		return self

	def transaction_to_json(self):
		return json.dumps(self.__dict__)

#classes
class StakeTransaction(Transaction):
	def __init__(self):
		Transaction.__init__(self)

	def create_stake_transaction(self, blocknumber, hashchain_terminator=None):
		self.epoch = int(blocknumber/c.blocks_per_epoch)	#in this block the epoch is..
		if hashchain_terminator == None:
			self.hash = my[0][1].hashchain_reveal(epoch=self.epoch+1) #my[0][1].hc_terminator
		else:
			self.hash = hashchain_terminator
		self.process_XMSS('ST', mining_address, self.hash) #self.hash to be replaced with self.txhash
		return self

	def validate_tx(self):
		if self.type != 'ST':
			return False
		for i in range(len(self.hash)):
			self.hash[i] = str(self.hash[i])

		if merkle.xmss_verify(str(self.hash), [self.i, self.signature, self.merkle_path, self.i_bms, self.pub, self.PK]) is False:
				return False
		if xmss_checkaddress(self.PK, self.txfrom) is False:
				return False

		return True

	def state_validate_tx(self):
		if self.type != 'ST':
			return False
		pub = self.pub
		pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]
		pubhash = sha256(''.join(pub))

		if pubhash in state_pubhash(self.txfrom):
			printL(( 'State validation failed for', self.hash, 'because: OTS Public key re-use detected'))
			return False

		return True

class SimpleTransaction(Transaction): 			#creates a transaction python class object which can be jsonpickled and sent into the p2p network..
	def __init__(self): # nonce removed..
		Transaction.__init__(self)
	
	def pre_condition(self):
		if state_uptodate() is False:
			printL(( 'Warning state not updated to allow safe tx validation, tx validity could be unreliable..'))
			#return False

		if state_balance(self.txfrom) is 0:
			printL(( 'State validation failed for', self.txhash, 'because: Empty address'))
			return False 

		if state_balance(self.txfrom) < self.amount: 
			printL(( 'State validation failed for', self.txhash,  'because: Insufficient funds'))
			return False
		return True
		
	def create_simple_transaction(self, txfrom, txto, amount, data, fee=0, hrs=''):
		self.txfrom = txfrom
		self.nonce = 0
		self.txto = txto
		self.amount = int(amount)
		self.fee = int(fee)
		self.ots_key = data.index

		pub = data.pk()
		pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]
		self.pubhash = sha256(''.join(pub))
		self.txhash = sha256(''.join(self.txfrom+str(self.pubhash)+self.txto+str(self.amount)+str(self.fee)))
		self.merkle_root = data.root
		if not self.pre_condition():
			return False
		#self.verify = data.VERIFY(self.txhash, S)			#not necessary, to save time could be commented out to reduce tx signing speed..
		self.process_XMSS('TX', txfrom, self.txhash)
		
		return self

	def validate_tx(self):
		#cryptographic checks
		if self.txhash != sha256(''.join(self.txfrom+str(self.pubhash))+self.txto+str(self.amount)+str(self.fee)):
			return False

		# SIG is a list composed of: i, s, auth_route, i_bms, pk[i], PK
		if self.type != 'TX':
			return False
		
		if merkle.xmss_verify(self.txhash, [self.i, self.signature, self.merkle_path, self.i_bms, self.pub, self.PK]) is False:
			return False
		if xmss_checkaddress(self.PK, self.txfrom) is False:
			return False
		
		return True		

	def state_validate_tx(self):		#checks new tx validity based upon node statedb and node mempool. 

		if not self.pre_condition():
			return False

		pub = self.pub
		if self.type != 'TX':
			return False

		pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]
		
		pubhash = sha256(''.join(pub))

		for txn in transaction_pool:
			if txn.txhash == self.txhash:
				continue
			pub = txn.pub
			if txn.type != 'TX':
				return False
			pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]

			pubhashn = sha256(''.join(pub))

			if pubhashn == pubhash:
				printL(( 'State validation failed for', self.txhash, 'because: OTS Public key re-use detected'))
				return False

		if pubhash in state_pubhash(self.txfrom):
			printL(( 'State validation failed for', self.txhash, 'because: OTS Public key re-use detected'))
			return False

		return True
		
def creategenesisblock():
	return CreateGenesisBlock()

class BlockHeader():
	def __init__(self, blocknumber, hashchain_link, prev_blockheaderhash, number_transactions, hashedtransactions, number_stake, hashedstake, reveal_list=None, last_block_number=-1):
		self.blocknumber = blocknumber
		self.hash = hashchain_link
		if self.blocknumber == 0:
			self.timestamp = 0
		else:
			self.timestamp = ntp.getTime()
			if self.timestamp == 0:
				printL (( 'Failed to get NTP timestamp' ))
				return
		self.prev_blockheaderhash = prev_blockheaderhash
		self.number_transactions = number_transactions
		self.merkle_root_tx_hash = hashedtransactions
		self.number_stake = number_stake
		self.hashedstake = hashedstake
		if self.blocknumber == 0:
			self.reveal_list = []
			self.stake_selector = ''
			self.stake_nonce = 0
			self.block_reward = 0
			self.epoch = 0
		elif self.blocknumber == 1:
			self.reveal_list = []
			tmp_chain, _ = select_hashchain(last_block_headerhash=block_chain_buffer.get_strongest_headerhash(0), hashchain=hash_chain, blocknumber=self.blocknumber)
			self.stake_nonce = c.blocks_per_epoch-tmp_chain.index(hashchain_link)			
			self.epoch = int(self.blocknumber/c.blocks_per_epoch)			#need to add in logic for epoch stake_list recalculation..
			self.stake_selector = mining_address
			self.block_reward = block_reward(self.blocknumber)
		else:
			self.reveal_list = reveal_list
			for s in block_chain_buffer.stake_list_get(self.blocknumber):
				if s[0] == mining_address:
					self.stake_nonce = s[2] + 1
			self.epoch = int(self.blocknumber/c.blocks_per_epoch)			#need to add in logic for epoch stake_list recalculation..
			self.stake_selector = mining_address
			self.block_reward = block_reward(self.blocknumber)

		self.headerhash = sha256(self.stake_selector+str(self.epoch)+str(self.stake_nonce)+str(self.block_reward)+str(self.timestamp)+self.hash+str(self.blocknumber)+self.prev_blockheaderhash+str(self.number_transactions)+self.merkle_root_tx_hash+str(self.number_stake)+self.hashedstake)

		data = my[0][1]
		S = data.SIGN(self.headerhash)
		self.i = S[0]
		self.signature = S[1]
		self.merkle_path = S[2]
		self.i_bms = S[3]
		self.pub = S[4]
		self.PK = S[5]




class CreateBlock():
	def __init__(self, hashchain_link, reveal_list=None, last_block_number=-1):
		#difficulty = 232
		data = None
		if last_block_number==-1:
			data = block_chain_buffer.get_last_block()	#m_get_last_block()
		else:
			data = block_chain_buffer.get_block_n(last_block_number)
		lastblocknumber = data.blockheader.blocknumber
		prev_blockheaderhash = data.blockheader.headerhash
		hashedtransactions = []
		for transaction in transaction_pool:
			if transaction.txhash not in block_chain_buffer.tx_buffer:
				hashedtransactions.append(transaction.txhash)
		if not hashedtransactions:
			hashedtransactions = sha256('')
		
		hashedtransactions = merkle_tx_hash(hashedtransactions)
		self.transactions = []
		for tx in transaction_pool:
			if tx.txhash not in block_chain_buffer.tx_buffer:
				self.transactions.append(tx)						#copy memory rather than sym link
		curr_epoch = int((last_block_number+1)/c.blocks_per_epoch)
		if not stake_pool:
			hashedstake = sha256('')
		else:
			sthashes = []
			for st in stake_pool:
				if st.epoch != curr_epoch:
					printL (( 'Skipping st as epoch mismatch, CreateBlock()' ))
					printL (( 'Expected st epoch : ', curr_epoch ))
					printL (( 'Found st epoch : ', st.epoch )) 
					continue
				if st.hash not in block_chain_buffer.st_buffer:
					sthashes.append(str(st.hash))
			hashedstake = sha256(''.join(sthashes))
		self.stake = []
		for st in stake_pool:
			if st.epoch != curr_epoch:
				printL (( 'Skipping st as epoch mismatch, CreateBlock()' ))
				printL (( 'Expected st epoch : ', curr_epoch ))
				printL (( 'Found st epoch : ', st.epoch )) 

				continue
			if st.hash not in block_chain_buffer.st_buffer:
				self.stake.append(st)

		self.blockheader = BlockHeader(blocknumber=lastblocknumber+1, reveal_list=reveal_list, hashchain_link=hashchain_link, prev_blockheaderhash=prev_blockheaderhash, number_transactions=len(transaction_pool), hashedtransactions=hashedtransactions, number_stake=len(stake_pool), hashedstake=hashedstake, last_block_number=last_block_number)
		if self.blockheader.timestamp == 0:
			printL(( 'Failed to create block due to timestamp 0' ))


class CreateGenesisBlock():			#first block has no previous header to reference..
	def __init__(self):
		self.blockheader = BlockHeader(blocknumber=0, hashchain_link='genesis', prev_blockheaderhash=sha256('quantum resistant ledger'),number_transactions=0, hashedtransactions=sha256('0'), number_stake=0, hashedstake=sha256('0'))
		self.transactions = []
		self.stake = []
		self.state = [['Q53500eec9d0bd5c3c8d61149ca31af2f9170ce1de202c466facee0d5c5050ede7f5e', [0, 10000*100000000, []]] , ['Q585ec74d5bb230aa00874fc40d00b4a32f9890ff491d159daf5a74e93787ba5fd476',[0, 10000*100000000,[]]], ['Qce8bc24fd9d3b9a828de5dfac5481d53b194b3d233345cdcee09b39ef837279ef1a1', [0, 10000*100000000,[]]] ]#, ['Q34eabf7ef2c6582096a433237a603b862fd5a70ac4efe4fd69faae21ca390512b3ac', [0, 10000*100000000,[]]], ['Qfc6a9b751915048a7888b65e77f9a248379d8b47c94081b3baced7c1234dc7f4b419', [0, 10000*100000000,[]]] ]
		#Qfc6a9b751915048a7888b65e77f9a248379d8b47c94081b3baced7c1234dc7f4b419 petal
		#Q4acc55bb7126f532cc1566242809153bb3cc8d360256aa94b7180ca4f7ffa555de57 tiddler
		#Q8eb5a51d4b8a4b53c5b8b9ded93d7fd7717796c3690bee0767b1dcaadd3520c1e242 twiglet
		#Q44328abd64300ce05c7b297f13ff9f02de4c0e40c5956a2168dd8c0a7c476bf613ce bean
		#Qa1f6f52ecb490cc3209a5e3580aa9539edfff0cb5a3ce06adc8f0c1e46bf38bfe0a0 flea
		self.stake_list = []
		for stake in self.state:
			self.stake_list.append(stake[0])
		#self.stake_list = ['Q0815e965f3f51740fe3ea03ed5ffcefc90be932f68f8e29d8b792b10ddfb95113167','Q287814bf7fc151fbbda6e4e613cca6da0f04f80c4ebd4ab59352d44d5e5fc2fe95f3','Qcdfe2d4eb5dd71d49b24bf73301de767936af38fbf640385c347aa398a5a1f777aee']
		#self.stake_list = ['Q8eb5a51d4b8a4b53c5b8b9ded93d7fd7717796c3690bee0767b1dcaadd3520c1e242', 'Qfc6a9b751915048a7888b65e77f9a248379d8b47c94081b3baced7c1234dc7f4b419','Q4acc55bb7126f532cc1566242809153bb3cc8d360256aa94b7180ca4f7ffa555de57','Q44328abd64300ce05c7b297f13ff9f02de4c0e40c5956a2168dd8c0a7c476bf613ce','Qa1f6f52ecb490cc3209a5e3580aa9539edfff0cb5a3ce06adc8f0c1e46bf38bfe0a0']
		#self.stake_list = ['Q775a5868cda4488f97436d1c7f45ddae68e896218dfe42f6233f46a72eebdb038066', 'Qe1563a15fe6ffae964473d11180aaace207bcb1ed1ac570dfb46684421f7bb4f10eb']
		self.stake_seed = '1a02aa2cbe25c60f491aeb03131976be2f9b5e9d0bc6b6d9e0e7c7fd19c8a076c29e028f5f3924b4'


class ReCreateBlock():						#recreate block class from JSON variables for processing
	def __init__(self, json_block):
		self.blockheader = ReCreateBlockHeader(json_block['blockheader'])
	
		transactions = json_block['transactions']
		self.transactions = []
		for tx in transactions:
			self.transactions.append(SimpleTransaction().dict_to_transaction(tx))

		stake = json_block['stake']
		self.stake = []
		
		for st in stake:
			st_obj = StakeTransaction().dict_to_transaction(st)
			if st_obj.epoch != self.blockheader.epoch:
				continue
			self.stake.append(st_obj)

class ReCreateBlockHeader():
	def __init__(self, json_blockheader):
		rl = json_blockheader['reveal_list']
		self.reveal_list = []
		for r in rl:								
				self.reveal_list.append(r.encode('latin1'))		
		self.stake_nonce = json_blockheader['stake_nonce']
		self.epoch = json_blockheader['epoch']
		self.headerhash = json_blockheader['headerhash'].encode('latin1')
		self.number_transactions = json_blockheader['number_transactions']
		self.number_stake = json_blockheader['number_stake']
		self.hash = json_blockheader['hash'].encode('latin1')
		self.timestamp = json_blockheader['timestamp']
		self.merkle_root_tx_hash = json_blockheader['merkle_root_tx_hash'].encode('latin1')
		self.hashedstake = json_blockheader['hashedstake'].encode('latin1')
		self.blocknumber = json_blockheader['blocknumber']
		self.prev_blockheaderhash = json_blockheader['prev_blockheaderhash'].encode('latin1')
		self.stake_selector = json_blockheader['stake_selector'].encode('latin1')
		self.block_reward = json_blockheader['block_reward']
		self.i = json_blockheader['i']
		self.signature = json_blockheader['signature']
		self.merkle_path = json_blockheader['merkle_path']
		self.i_bms = json_blockheader['i_bms']
		self.pub = json_blockheader['pub']
		self.PK = json_blockheader['PK']

# address functions

# for xmss

def xmss_rootoaddr(PK_short):
	return 'Q'+sha256(PK_short[0]+PK_short[1])+sha256(sha256(PK_short[0]+PK_short[1]))[:4]

def xmss_checkaddress(PK_short, address):
	if 'Q'+sha256(PK_short[0]+PK_short[1])+sha256(sha256(PK_short[0]+PK_short[1]))[:4] == address:
		return True
	return False

# for mss

def roottoaddr(merkle_root):
	return 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4]

def checkaddress(merkle_root, address):
	if 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4] == address:
		return True
	return False

# block reward calculation
# decay curve: 200 years (until 2217AD, 420480000 blocks at 15s block-times)
# N_tot is less the initial coin supply.

def calc_coeff(N_tot, block_tot):
	# lambda = Ln N_0 - Ln (N(t)) / t
	return log(N_tot)/block_tot

# calculate remaining emission at block_n: N=total initial coin supply, coeff = decay constant
# need to use decimal as floating point not precise enough on different platforms..

#def remaining_emission(N_tot,block_n):
#	coeff = calc_coeff(21000000, 420480000)
	# N_t = N_0.e^{-coeff.t} where t = block
#	return N_tot*e**(-coeff*block_n)

def remaining_emission(N_tot, block_n):
	coeff = calc_coeff(21000000, 420480000)
	return decimal.Decimal(N_tot*decimal.Decimal(-coeff*block_n).exp()).quantize(decimal.Decimal('1.00000000'), rounding=decimal.ROUND_HALF_UP)

# return block reward for the block_n 

def block_reward(block_n):
	return int((remaining_emission(21000000, block_n-1)-remaining_emission(21000000, block_n))*100000000)

# network serialising functions

def json_decode_st(json_tx):
	return ReCreateStakeTransaction(json.loads(json_tx))

def json_decode_tx(json_tx):										#recreate transaction class object safely 
	return ReCreateSimpleTransaction(json.loads(json_tx))

def json_decode_block(json_block):
	return ReCreateBlock(json.loads(json_block))

def json_encode(obj):
	return json.dumps(obj)

def json_decode(js_obj):
	return json.loads(js_obj)

class ComplexEncoder(json.JSONEncoder):
	def default(self, obj):
		return obj.__dict__

def json_encode_complex(obj):
	return json.dumps(obj, cls=ComplexEncoder)
	
def json_bytestream(obj):	
	return json.dumps(obj.__dict__, cls=ComplexEncoder)

def json_bytestream_tx(tx_obj):											#JSON serialise tx object
	return json_bytestream(tx_obj)

def json_bytestream_pb(block_obj):
	return json_bytestream(block_obj)

def json_bytestream_ph(mini_block):
	return json_encode(mini_block)

def json_bytestream_bk(block_obj):										# "" block object
	return json_bytestream(block_obj)

def json_print(obj):													#prettify output from JSON for export purposes
	printL(( json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False)), indent=4)))

def json_print_telnet(obj):
	return json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False)), indent=4)

# tx, address chain search functions

def search_telnet(txcontains, long=1):
	tx_list = []
	hrs_list = []

	#because we allow hrs substitution in txto for transactions, we need to identify where this occurs for searching..

	if txcontains[0] == 'Q':
		for block in m_blockchain:
			for tx in block.transactions:
				if tx.txfrom == txcontains:
					if len(tx.hrs) > 0:
						if state_hrs(tx.hrs) == txcontains:
							hrs_list.append(tx.hrs)

	for tx in transaction_pool:
		if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains or tx.txto in hrs_list:
			#printL(( txcontains, 'found in transaction pool..'
			if long==0: tx_list.append('<tx:txhash> '+tx.txhash+' <transaction_pool>')
			if long==1: tx_list.append(json_print_telnet(tx))

	for block in m_blockchain:
		for tx in block.transactions:
			if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains or tx.txto in hrs_list:
				#printL(( txcontains, 'found in block',str(block.blockheader.blocknumber),'..'
				if long==0: tx_list.append('<tx:txhash> '+tx.txhash+' <block> '+str(block.blockheader.blocknumber))
				if long==1: tx_list.append(json_print_telnet(tx))
	return tx_list

# used for port 80 api - produces JSON output of a specific tx hash, including status of tx, in a block or unconfirmed + timestampe of parent block

def search_txhash(txhash):				#txhash is unique due to nonce.
	for tx in transaction_pool:
		if tx.txhash == txhash:
			printL(( txhash, 'found in transaction pool..'))
			tx_new = copy.deepcopy(tx)
			tx_new.block = 'unconfirmed'
			tx_new.hexsize = len(json_bytestream(tx_new))
			tx_new.status = 'ok'
			return json_print_telnet(tx_new)
	for block in m_blockchain:
		for tx in block.transactions:
			if tx.txhash== txhash:
				tx_new = copy.deepcopy(tx)
				tx_new.block = block.blockheader.blocknumber
				tx_new.timestamp = block.blockheader.timestamp
				tx_new.confirmations = m_blockheight()-block.blockheader.blocknumber
				tx_new.hexsize = len(json_bytestream(tx_new))
				tx_new.amount = tx_new.amount/100000000.000000000
				tx_new.fee = tx_new.fee/100000000.000000000
				printL(( txhash, 'found in block',str(block.blockheader.blocknumber),'..'))
				tx_new.status = 'ok'
				return json_print_telnet(tx_new)
	printL(( txhash, 'does not exist in memory pool or local blockchain..'))
	err = {'status' : 'Error', 'error' : 'txhash not found', 'method' : 'txhash', 'parameter' : txhash}
	return json_print_telnet(err)
	#return False

# used for port 80 api - produces JSON output reporting every transaction for an address, plus final balance..

def search_address(address):
	
	addr = {}
	addr['transactions'] = {}


	if state_address_used(address) != False:
		nonce, balance, pubhash_list = state_get_address(address)
		addr['state'] = {}
		addr['state']['address'] = address
		addr['state']['balance'] = balance/100000000.000000000
		addr['state']['nonce'] = nonce

	for s in stake_list_get():
		if address == s[0]:
			addr['stake'] = {}
			addr['stake']['selector'] = s[2]
		#pubhashes used could be put here..

	for tx in transaction_pool:
		if tx.txto == address or tx.txfrom == address:
			printL(( address, 'found in transaction pool'))
			addr['transactions'][tx.txhash] = {}
			addr['transactions'][tx.txhash]['txhash'] = tx.txhash
			addr['transactions'][tx.txhash]['block'] = 'unconfirmed'
			addr['transactions'][tx.txhash]['amount'] = tx.amount/100000000.000000000
			addr['transactions'][tx.txhash]['fee'] = tx.fee/100000000.000000000
			addr['transactions'][tx.txhash]['nonce'] = tx.nonce
			addr['transactions'][tx.txhash]['ots_key'] = tx.ots_key
			addr['transactions'][tx.txhash]['txto'] = tx.txto
			addr['transactions'][tx.txhash]['txfrom'] = tx.txfrom
			addr['transactions'][tx.txhash]['timestamp'] = 'unconfirmed'


	for block in m_blockchain:
		for tx in block.transactions:
		 if tx.txto == address or tx.txfrom == address:
			printL(( address, 'found in block ', str(block.blockheader.blocknumber), '..' ))
			addr['transactions'][tx.txhash]= {}
			addr['transactions'][tx.txhash]['txhash'] = tx.txhash
			addr['transactions'][tx.txhash]['block'] = block.blockheader.blocknumber
			addr['transactions'][tx.txhash]['timestamp'] = block.blockheader.timestamp
			addr['transactions'][tx.txhash]['amount'] = tx.amount/100000000.000000000
			addr['transactions'][tx.txhash]['fee'] = tx.fee/100000000.000000000
			addr['transactions'][tx.txhash]['nonce'] = tx.nonce
			addr['transactions'][tx.txhash]['ots_key'] = tx.ots_key
			addr['transactions'][tx.txhash]['txto'] = tx.txto
			addr['transactions'][tx.txhash]['txfrom'] = tx.txfrom	

	if len(addr['transactions']) > 0:
		addr['state']['transactions'] = len(addr['transactions'])
	

	if addr == {'transactions': {}}:
		addr = {'status': 'error', 'error' : 'address not found', 'method' : 'address', 'parameter' : address}
	else:
		addr['status'] = 'ok'


	return json_print_telnet(addr)

# return json info on last n tx in the blockchain

def last_tx(n=None):

	addr = {}
	addr['transactions'] = {}

	error = {'status': 'error', 'error' : 'invalid argument', 'method' : 'last_tx', 'parameter' : n}

	if not n:
		n = 1

	try: 	n = int(n)
 	except: return json_print_telnet(error)

 	if n <= 0 or n > 20:
 		return json_print_telnet(error)

 	if len(transaction_pool) != 0:
 		if n-len(transaction_pool) >=0:		# request bigger than tx in pool
 			z = len(transaction_pool)
 			n = n-len(transaction_pool)
 		elif n-len(transaction_pool) <=0:	# request smaller than tx in pool..
 			z = n
 			n = 0
 	
 	 	for tx in reversed(transaction_pool[-z:]):
 	 		addr['transactions'][tx.txhash] = {}
 	 		addr['transactions'][tx.txhash]['txhash'] = tx.txhash
			addr['transactions'][tx.txhash]['block'] = 'unconfirmed'
			addr['transactions'][tx.txhash]['timestamp'] = 'unconfirmed'
			addr['transactions'][tx.txhash]['amount'] = tx.amount/100000000.000000000
			addr['transactions'][tx.txhash]['type'] = tx.type

		if n == 0:
			addr['status'] = 'ok'
			return json_print_telnet(addr)


	for block in reversed(m_blockchain):
			if len(block.transactions) > 0:
				for tx in reversed(block.transactions):
					addr['transactions'][tx.txhash] = {}
 	 				addr['transactions'][tx.txhash]['txhash'] = tx.txhash
					addr['transactions'][tx.txhash]['block'] = block.blockheader.blocknumber
					addr['transactions'][tx.txhash]['timestamp'] = block.blockheader.timestamp
					addr['transactions'][tx.txhash]['amount'] = tx.amount/100000000.000000000
					addr['transactions'][tx.txhash]['type'] = tx.type
					n-=1
					if n == 0:
						addr['status'] = 'ok'
						return json_print_telnet(addr)
	return json_print_telnet(error)

def richlist(n=None):			#only feasible while chain is small..
	if not n:
		n = 5

	error = {'status': 'error', 'error' : 'invalid argument', 'method' : 'richlist', 'parameter' : n}

	try: n=int(n)
	except: return json_print_telnet(error)

	if n<=0 or n > 20:
		return json_print_telnet(error)

	if state_uptodate()==False:
		return json_print_telnet({'status': 'error', 'error': 'leveldb failed', 'method': 'richlist'})

	addr = db.return_all_addresses()
	richlist = sorted(addr, key=itemgetter(1), reverse=True)

	rl = {}
	rl['richlist'] = {}

	if len(richlist) < n:
		n = len(richlist)

	for rich in richlist[:n]:
		rl['richlist'][richlist.index(rich)+1] = {}
		rl['richlist'][richlist.index(rich)+1]['address'] = rich[0]
		rl['richlist'][richlist.index(rich)+1]['balance'] = rich[1]/100000000.000000000

	rl['status'] = 'ok'

	return json_print_telnet(rl)

# return json info on last n blocks

def last_block(n=None):

	if not n:
		n = 1

	error = {'status': 'error', 'error' : 'invalid argument', 'method' : 'last_block', 'parameter' : n}

	try: 	n=int(n)
	except: return json_print_telnet(error)	

	if n <= 0 or n > 20:
		return json_print_telnet(error)

	lb = m_blockchain[-n:]

	last_blocks = {}
	last_blocks['blocks'] = {}

	for block in reversed(lb):

		last_blocks['blocks'][block.blockheader.blocknumber] = {}
		last_blocks['blocks'][block.blockheader.blocknumber]['block_reward'] = block.blockheader.block_reward/100000000.00000000
		last_blocks['blocks'][block.blockheader.blocknumber]['blocknumber'] = block.blockheader.blocknumber
		last_blocks['blocks'][block.blockheader.blocknumber]['blockhash'] = block.blockheader.prev_blockheaderhash
		last_blocks['blocks'][block.blockheader.blocknumber]['number_transactions'] = block.blockheader.number_transactions
		last_blocks['blocks'][block.blockheader.blocknumber]['number_stake'] = block.blockheader.number_stake
		last_blocks['blocks'][block.blockheader.blocknumber]['timestamp'] = block.blockheader.timestamp
		last_blocks['blocks'][block.blockheader.blocknumber]['block_interval'] = block.blockheader.timestamp - m_blockchain[block.blockheader.blocknumber-1].blockheader.timestamp

	last_blocks['status'] = 'ok'

	return json_print_telnet(last_blocks)

# return json info on stake_commit list

def stake_commits(data=None):

	sc = {}
	sc['status'] = 'ok'
	sc['commits'] = {}

	for c in stake_commit:
		#[stake_address, block_number, merkle_hash_tx, commit_hash]
		sc['commits'][str(c[1])+'-'+c[3]] = {}
		sc['commits'][str(c[1])+'-'+c[3]]['stake_address'] = c[0]
		sc['commits'][str(c[1])+'-'+c[3]]['block_number'] = c[1]
		sc['commits'][str(c[1])+'-'+c[3]]['merkle_hash_tx'] = c[2]
		sc['commits'][str(c[1])+'-'+c[3]]['commit_hash'] = c[3]


	return json_print_telnet(sc)

def stakers(data=None):
	#(stake -> address, hash_term, nonce)
	stakers = {}
	stakers['status'] = 'ok'
	stakers['stake_list'] = {}
	for s in stake_list_get():
		stakers['stake_list'][s[0]] = {}
		stakers['stake_list'][s[0]]['address'] = s[0]
		stakers['stake_list'][s[0]]['balance'] = state_balance(s[0])/100000000.00000000
		stakers['stake_list'][s[0]]['hash_terminator'] = s[1]
		stakers['stake_list'][s[0]]['nonce'] = s[2]
		
	return json_print_telnet(stakers)

def next_stakers(data=None):
	#(stake -> address, hash_term, nonce)
	next_stakers = {}
	next_stakers['status'] = 'ok'
	next_stakers['stake_list'] = {}
	for s in next_stake_list_get():
		next_stakers['stake_list'][s[0]] = {}
		next_stakers['stake_list'][s[0]]['address'] = s[0]
		next_stakers['stake_list'][s[0]]['balance'] = state_balance(s[0])/100000000.00000000
		next_stakers['stake_list'][s[0]]['hash_terminator'] = s[1]
		next_stakers['stake_list'][s[0]]['nonce'] = s[2]
		
	return json_print_telnet(next_stakers)

def exp_win(data=None):
	# chain.expected_winner.append([chain.m_blockchain[-1].blockheader.blocknumber+1, winner, winning_staker])
	ew = {}
	ew['status'] = 'ok'
	ew['expected_winner'] = {}
	for e in expected_winner:
		ew['expected_winner'][e[0]] = {}
		ew['expected_winner'][e[0]]['hash'] = e[1]
		ew['expected_winner'][e[0]]['stake_address'] = e[2]
	return json_print_telnet(ew)

def stake_reveal_ones(data=None):

	sr = {}
	sr['status'] = 'ok'
	sr['reveals'] = {}
	# chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one]) #merkle_hash_tx, commit_hash])
	for c in stake_reveal_one:
		sr['reveals'][str(c[1])+'-'+str(c[2])] = {}
		sr['reveals'][str(c[1])+'-'+str(c[2])]['stake_address'] = c[0]
		sr['reveals'][str(c[1])+'-'+str(c[2])]['block_number'] = c[2]
		sr['reveals'][str(c[1])+'-'+str(c[2])]['headerhash'] = c[1]
		sr['reveals'][str(c[1])+'-'+str(c[2])]['reveal'] = c[3]

	return json_print_telnet(sr)

def ip_geotag(data=None):
	
	ip = {}
	ip['status'] = 'ok'
	ip['ip_geotag'] = {}
	ip['ip_geotag'] = ip_list

	x=0
	for i in ip_list:
		ip['ip_geotag'][x] = i
		x+=1

	return json_print_telnet(ip)

def stake_reveals(data=None):

	sr = {}
	sr['status'] = 'ok'
	sr['reveals'] = {}
	#chain.stake_reveal.append([stake_address, block_number, merkle_hash_tx, reveal])
	for c in stake_reveal:
		sr['reveals'][str(c[1])+'-'+c[3]] = {}
		sr['reveals'][str(c[1])+'-'+c[3]]['stake_address'] = c[0]
		sr['reveals'][str(c[1])+'-'+c[3]]['block_number'] = c[1]
		sr['reveals'][str(c[1])+'-'+c[3]]['merkle_hash_tx'] = c[2]
		sr['reveals'][str(c[1])+'-'+c[3]]['reveal'] = c[3]

	return json_print_telnet(sr)

def search(txcontains, long=1):
	for tx in transaction_pool:
		if tx.txhash == txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
			printL(( txcontains, 'found in transaction pool..'))
			if long==1: json_print(tx)
	for block in m_blockchain:
		for tx in block.transactions:
			if tx.txhash== txcontains or tx.txfrom == txcontains or tx.txto == txcontains:
				printL(( txcontains, 'found in block',str(block.blockheader.blocknumber),'..'))
				if long==0: printL(( '<tx:txhash> '+tx.txhash))
				if long==1: json_print(tx)
	return

# chain functions

def f_chain_exist():
	if os.path.isfile('./chain.dat') is True:
		return True
	return False

def f_read_chain():
	block_list = []
	if os.path.isfile('./chain.dat') is False:
		printL(( 'Creating new chain file'))
		block_list.append(creategenesisblock())
		with open("./chain.dat", "a") as myfile:				#add in a new call to create random_otsmss
        		pickle.dump(block_list, myfile)
	try:
			with open('./chain.dat', 'r') as myfile:
				return pickle.load(myfile)
	except:
			printL(( 'IO error'))
			return False

def f_get_last_block():
	return f_read_chain()[-1]

def f_write_chain(block_data):											
		data = f_read_chain()
		for block in block_data:
				data.append(block)
		if block_data is not False:
			printL(( 'Appending data to chain'))
			with open("./chain.dat", "w+") as myfile:				#overwrites wallet..must use w+ as cannot append pickle item
        			pickle.dump(data, myfile)
		return


def f_write_m_blockchain():
	printL(( 'Appending data to chain'))
	with open("./chain.dat", "w+") as myfile:
			pickle.dump(m_blockchain, myfile)
	return

def m_load_chain():

	del m_blockchain[:]
	chains = f_read_chain()
	m_blockchain.append(chains[0])
	state_read_genesis()
	global block_chain_buffer
	block_chain_buffer = ChainBuffer()

	for block in chains[1:]:
		block_chain_buffer.add_block_mainchain(block, verify_block_reveal_list=False, validate=False)
	return m_blockchain

def m_read_chain():
	if not m_blockchain:
		m_load_chain()
	return m_blockchain

def m_get_block(n):
	if n > len(m_blockchain)-1 or n < 0:
		return False
	return m_read_chain()[n]

def m_get_last_block():
	return m_read_chain()[-1]

def m_create_block(nonce, reveal_list=None, last_block_number=-1):
	return CreateBlock(nonce, reveal_list, last_block_number)

def m_add_block(block_obj, verify_block_reveal_list=True):
	if len(m_blockchain) == 0:
		m_read_chain()

	if validate_block(block_obj, verify_block_reveal_list=verify_block_reveal_list) is True:
		if state_add_block(block_obj) is True:
				m_blockchain.append(block_obj)
				remove_tx_in_block_from_pool(block_obj)
				remove_st_in_block_from_pool(block_obj)
		else: 	
				printL(( 'last block failed state/stake checks, removed from chain' ))
				state_validate_tx_pool()
				return False
	else:
		printL(( 'm_add_block failed - block failed validation.' ))
		return False
	m_f_sync_chain()
	return True

def m_remove_last_block():
	if not m_blockchain:
		m_read_chain()
	m_blockchain.pop()

def m_blockheight():
	return len(m_read_chain())-1

def height():
	return len(m_blockchain)-1

def m_info_block(n):
	if n > m_blockheight():
		printL(( 'No such block exists yet..'))
		return False
	b = m_get_block(n)
	printL(( 'Block: ', b, str(b.blockheader.blocknumber)))
	printL(( 'Blocksize, ', str(len(json_bytestream(b)))))
	printL(( 'Number of transactions: ', str(len(b.transactions))))
	printL(( 'Validates: ', validate_block(b)))

def m_f_sync_chain():

	if m_blockchain[-1].blockheader.blocknumber % 1 == 0:
		f_write_m_blockchain()
	return

def m_verify_chain(verbose=0):
	n = 0
	for block in m_read_chain()[1:]:
		if validate_block(block, verbose=verbose) is False:
				return False
		n+=1
		if verbose is 1:
			sys.stdout.write('.')
			sys.stdout.flush()
	return True


def m_verify_chain_250(verbose=0):		#validate the last 250 blocks or len(m_blockchain)-1..
	n = 0
	if len(m_blockchain) > 250:
		x = 250
	else:
		if len(m_blockchain)==1:
			return True
		x = len(m_blockchain) -1

	for block in m_read_chain()[-x:]:
		if validate_block(block, verbose=verbose) is False:
				printL(( 'block failed:', block.blockheader.blocknumber))
				return False
		n+=1
		if verbose is 1:
			sys.stdout.write('.')
			sys.stdout.flush()
	return True

#state functions
#first iteration - state data stored in leveldb file
#state holds address balances, the transaction nonce and a list of pubhash keys used for each tx - to prevent key reuse.

def state_load_peers():
	if os.path.isfile('./peers.dat') is True:
		printL(( 'Opening peers.dat'))
		with open('./peers.dat', 'r') as myfile:
			state_put_peers(pickle.load(myfile))
	else:
		printL(( 'Creating peers.dat'))
	 	with open('./peers.dat', 'w+') as myfile:
			pickle.dump(node_list, myfile)
			state_put_peers(node_list)

def state_save_peers():
	with open("./peers.dat", "w+") as myfile:			
        			pickle.dump(state_get_peers(), myfile)

def state_get_peers():
	try: return db.get('node_list')
	except: return False
	
def state_put_peers(peer_list):
	try: db.put('node_list', peer_list)
	except: return False

def stake_list_get():
	try: return db.get('stake_list')
	except: return []

def stake_list_put(sl):
	try: db.put('stake_list', sl)
	except: return False

def next_stake_list_get():
	try: return db.get('next_stake_list')
	except: return []

def next_stake_list_put(next_sl):
	try: db.put('next_stake_list', next_sl)
	except: return False

def state_uptodate():									#check state db marker to current blockheight.
	if m_blockheight() == db.get('blockheight'):
		return True
	return False

def state_blockheight():
	return db.get('blockheight')

def state_get_address(addr):
	try: return db.get(addr)
	except:	return [0,0,[]]

def state_address_used(addr):							#if excepts then address does not exist..
	try: return db.get(addr)
	except: return False 

def state_balance(addr):
	try: return db.get(addr)[1]
	#except:	return False
	except:	return 0 

def state_nonce(addr):
	try: return db.get(addr)[0]
	except: return 0
	#except:	return False

def state_pubhash(addr):
	try: return db.get(addr)[2]
	except: return []
	#except:	return False

def state_hrs(hrs):
	try: return db.get('hrs'+hrs)
	except: return False

def state_validate_tx_pool():
	x=0
	for tx in transaction_pool:
		if tx.state_validate_tx() is False:
			x+=1
			printL(( 'tx', tx.txhash, 'failed..'))
			remove_tx_from_pool(tx)
	if x > 0:
		return False
	return True

# validate and update stake+state for newly appended block.
# can be streamlined to reduce repetition in the added components..
# finish next epoch code..

def state_add_block(block):
	global hash_chain
	
	address_txn = {}

	address_txn[block.blockheader.stake_selector] = state_get_address(block.blockheader.stake_selector)

	for st in block.stake:
		if st.txfrom not in address_txn:
			address_txn[st.txfrom] = state_get_address(st.txfrom)

	for tx in block.transactions:
		if tx.txfrom not in address_txn:
			address_txn[tx.txfrom] = state_get_address(tx.txfrom)
		if tx.txto not in address_txn:
			address_txn[tx.txto] = state_get_address(tx.txto)

	# reminder contents: (state address -> nonce, balance, [pubhash]) (stake -> address, hash_term, nonce)

	next_sl = next_stake_list_get()
	sl = stake_list_get()

	blocks_left = block.blockheader.blocknumber - (block.blockheader.epoch*c.blocks_per_epoch)
	blocks_left = c.blocks_per_epoch-blocks_left

	if block.blockheader.blocknumber == 1: 	# if block 1: 

		for st in block.stake:

			if st.txfrom == block.blockheader.stake_selector:			#update txfrom, hash and stake_nonce against genesis for current or next stake_list
				if st.txfrom in m_blockchain[0].stake_list:
					sl.append([st.txfrom, st.hash, 1])
				else:
					printL(( 'designated staker not in genesis..'))
					return False
			else:
				if st.txfrom in m_blockchain[0].stake_list:
					sl.append([st.txfrom, st.hash, 0])
				else:
					next_sl.append([st.txfrom, st.hash, 0])

			pub = st.pub
			pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]
			pubhash = sha256(''.join(pub))
			address_txn[st.txfrom][2].append(pubhash)
			
			printL(( 'state st.txfrom', state_get_address(st.txfrom)))

		stake_list = sorted(sl, key=itemgetter(1))

		#numlist(stake_list)
		global epoch_PRF
		global epoch_prf
		epoch_PRF = merkle.GEN_range(m_blockchain[block.blockheader.epoch*c.blocks_per_epoch].stake_seed, 1, c.blocks_per_epoch, 32)
		block_chain_buffer.epoch_PRF[0] = epoch_PRF
		epoch_prf = pos_block_selector(m_blockchain[block.blockheader.epoch*c.blocks_per_epoch].stake_seed, len(stake_list))		#need to add a stake_seed option in block classes
		if stake_list[epoch_prf[block.blockheader.blocknumber-block.blockheader.epoch*c.blocks_per_epoch]][0] != block.blockheader.stake_selector:
				printL(( 'stake selector wrong..'))
				return

		my[0][1].hashchain(epoch=0)
		hash_chain = my[0][1].hc
		wallet.f_save_wallet()

	else:

		found = False
			
		#increase the stake_nonce of state selector..must be in stake list..
		printL(( 'BLOCK:', block.blockheader.blocknumber, 'stake nonce:', block.blockheader.stake_nonce, 'epoch: ', block.blockheader.epoch, 'blocks_left: ', blocks_left-1, 'stake_selector: ', block.blockheader.stake_selector ))

		for s in sl:
			if block.blockheader.stake_selector == s[0]:
				found = True
				s[2] += 1
				if s[2] != block.blockheader.stake_nonce:
					printL(( 'stake_nonce wrong..'))
					printL(( 'block STake Selector ', block.blockheader.stake_selector ))
					printL(( 'Expected Nonce ', str(s[2]) ))
					printL(( 'Actual Nonce ', str(block.blockheader.stake_nonce) ))
					return
				break

		if not found:
			printL(( 'stake selector not in stake_list_get'))
			return

		# update and re-order the next_stake_list:

		for st in block.stake:
			pub = st.pub
			pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]
			pubhash = sha256(''.join(pub))
			found = False

			for s in next_sl:
				if st.txfrom == s[0]:		#already in the next stake list, ignore for staker list but update as usual the state_for_address..
					found = True
					break

			address_txn[st.txfrom][2].append(pubhash)

			if not found:
				next_sl.append([st.txfrom, st.hash, 0])


	# cycle through every tx in the new block to check state
	
	for tx in block.transactions:

		pub = tx.pub
		if tx.type == 'TX':
				pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]

		pubhash = sha256(''.join(pub))
		
		# basic tx state checks..

		#if s1[1] - tx.amount < 0:
		if address_txn[tx.txfrom][1] - tx.amount < 0:
			printL(( tx, tx.txfrom, 'exceeds balance, invalid tx'))
			return False

		if tx.nonce != address_txn[tx.txfrom][0]+1:
			printL(( 'nonce incorrect, invalid tx'))
			printL(( tx, tx.txfrom, tx.nonce))
			return False

		if pubhash in address_txn[tx.txfrom][2]:
			printL(( 'pubkey reuse detected: invalid tx', tx.txhash))
			return False

		# add a check to prevent spend from stake address..
		# if tx.txfrom in stake_list_get():
		# printL(( 'attempt to spend from a stake address: invalid tx type'
		# break

		address_txn[tx.txfrom][0] += 1
		address_txn[tx.txfrom][1] -= tx.amount
		address_txn[tx.txfrom][2].append(pubhash)

		address_txn[tx.txto][1] = address_txn[tx.txto][1] + tx.amount

	# committing state

	# first the coinbase address is updated
	address_txn[block.blockheader.stake_selector][1] += block.blockheader.block_reward

	for address in address_txn:
		db.put(address, address_txn[address])

	if block.blockheader.blocknumber > 1 or block.blockheader.blocknumber == 1:
		stake_list_put(sl)
		next_stake_list_put(sorted(next_sl, key=itemgetter(1)))

	if blocks_left == 1:
		printL(( 'EPOCH change: resetting stake_list, activating next_stake_list, updating PRF with seed+entropy, updating wallet hashchains..'))
		
		sl = next_sl
		stake_list_put(sl)
		del next_sl[:] 
		next_stake_list_put(next_sl)

		my[0][1].hashchain(epoch=block.blockheader.epoch+1)
		hash_chain = my[0][1].hc
		wallet.f_save_wallet()

	db.put('blockheight', m_blockheight()+1)
	printL(( block.blockheader.headerhash, str(len(block.transactions)),'tx ',' passed verification.'))
	return True

def state_read_genesis():
	printL(( 'genesis:'))
	db.zero_all_addresses()
	c = m_get_block(0).state
	for address in c:
		db.put(address[0], address[1])
	return True

def state_read_chain():

	db.zero_all_addresses()
	c = m_get_block(0).state
	for address in c:
		db.put(address[0], address[1])
	
	c = m_read_chain()[2:]
	for block in c:

		# update coinbase address state
		stake_selector = state_get_address(block.blockheader.stake_selector)
		stake_selector[1]+=block.blockheader.block_reward
		db.put(block.blockheader.stake_selector, stake_selector)

		for tx in block.transactions:
			pub = tx.pub
			if tx.type == 'TX':
					pub = [''.join(pub[0][0]),pub[0][1],''.join(pub[2:])]

			pubhash = sha256(''.join(pub))

			s1 = state_get_address(tx.txfrom)

			if s1[1] - tx.amount < 0:
				printL(( tx, tx.txfrom, 'exceeds balance, invalid tx', tx.txhash))
				printL(( block.blockheader.headerhash, 'failed state checks'))
				return False

			if tx.nonce != s1[0]+1:
				printL(( 'nonce incorrect, invalid tx', tx.txhash))
				printL(( block.blockheader.headerhash, 'failed state checks'))
				return False

			if pubhash in s1[2]:
				printL(( 'public key re-use detected, invalid tx', tx.txhash))
				printL(( block.blockheader.headerhash, 'failed state checks'))
				return False

			s1[0]+=1
			s1[1] = s1[1]-tx.amount
			s1[2].append(pubhash)
			db.put(tx.txfrom, s1)							#must be ordered in case tx.txfrom = tx.txto

			s2 = state_get_address(tx.txto)
			s2[1] = s2[1]+tx.amount
			
			db.put(tx.txto, s2)

		printL(( block, str(len(block.transactions)), 'tx ', ' passed'))
	db.put('blockheight', m_blockheight())
	return True

def add_tx_to_pool(tx_class_obj):
	transaction_pool.append(tx_class_obj)
	txhash_timestamp.append(tx_class_obj.txhash)
	txhash_timestamp.append(time())

def add_st_to_pool(st_class_obj):
	stake_pool.append(st_class_obj)

def remove_tx_from_pool(tx_class_obj):
	transaction_pool.remove(tx_class_obj)
	txhash_timestamp.pop(txhash_timestamp.index(tx_class_obj.txhash)+1)
	txhash_timestamp.remove(tx_class_obj.txhash)

def remove_st_from_pool(st_class_obj):
	stake_pool.remove(st_class_obj)
	
def show_tx_pool():
	return transaction_pool

def remove_tx_in_block_from_pool(block_obj):
	for tx in block_obj.transactions:
		for txn in transaction_pool:
			if tx.txhash == txn.txhash:
				remove_tx_from_pool(txn)

def remove_st_in_block_from_pool(block_obj):
	for st in block_obj.stake:
		for stn in stake_pool:
			if st.hash == stn.hash:
				remove_st_from_pool(stn)

def flush_tx_pool():
	del transaction_pool[:]

def flush_st_pool():
	del stake_pool[:]

def validate_tx_in_block(block_obj):
	x = 0
	for transaction in block_obj.transactions:
		if transaction.validate_tx() is False:
			printL(( 'invalid tx: ',transaction, 'in block'))
			x+=1
	if x > 0:
		return False
	return True

def validate_st_in_block(block_obj):
	x = 0
	for st in block_obj.stake:
		if st.validate_tx() is False:
			printL(( 'invalid st:', st, 'in block'))
			x+=1
	if x > 0:
		return False
	return True

def validate_tx_pool():									#invalid transactions are auto removed from pool..
	for transaction in transaction_pool:
		if transaction.validate_tx() is False:
			remove_tx_from_pool(transaction)
			printL(( 'invalid tx: ',transaction, 'removed from pool'))

	return True


# block validation

def validate_block(block, verbose=0, verify_block_reveal_list=True):		#check validity of new block..
	b = block.blockheader
	last_block = b.blocknumber - 1

	if merkle.xmss_verify(b.headerhash, [b.i, b.signature, b.merkle_path, b.i_bms, b.pub, b.PK]) is False:
		printL (( 'BLOCK : merkle xmss_verify failed for the block' ))
		return False

	if xmss_checkaddress(b.PK, b.stake_selector) is False:
		printL (( 'BLOCK : xmss checkaddress failed' ))
		return False

	if b.timestamp == 0 and b.blocknumber > 0:
		printL(( 'Invalid block timestamp ' ))
		return False


	if b.block_reward != block_reward(b.blocknumber):
		printL(( 'Block reward incorrect for block: failed validation'))
		return False

	if b.epoch != b.blocknumber/c.blocks_per_epoch:
		printL(( 'Epoch incorrect for block: failed validation'))

	if b.blocknumber == 1:
		x=0
		for st in block.stake:
			if st.txfrom == b.stake_selector:
				x = 1
				hash, _ = select_hashchain(m_blockchain[-1].blockheader.headerhash, b.stake_selector, st.hash, blocknumber=1)

				if sha256(b.hash) != hash or hash not in st.hash:
					printL(( 'Hashchain_link does not hash correctly to terminator: failed validation'))
					return False
		if x != 1:
			printL(( 'Stake selector not in block.stake: failed validation'))
			return False
	else:		# we look in stake_list for the hash terminator and hash to it..
		y=0
		terminator = sha256(b.hash)
		for x in range(b.blocknumber-(b.epoch*c.blocks_per_epoch)):
			terminator = sha256(terminator)

		for st in stake_list_get():
			if st[0] == b.stake_selector:
				y = 1
				hash, _ = select_hashchain(block_chain_buffer.get_strongest_headerhash(last_block), b.stake_selector, blocknumber=b.blocknumber)

				if terminator != hash or hash not in st[1]:
					printL(( 'Supplied hash does not iterate to terminator: failed validation'))
					return False
		if y != 1:
				printL(( 'Stake selector not in stake_list for this epoch..'))
				return False
	

	if b.blocknumber > 1:
		if b.hash not in select_winners(b.reveal_list, topN=3, blocknumber=b.blocknumber, block=block):
			printL(( "Closest hash not in block selector.."))
			return False
		
		if len(b.reveal_list) != len(set(b.reveal_list)):
			printL(( 'Repetition in reveal_list'))
			return False

	 	if verify_block_reveal_list:

			i=0
			for r in b.reveal_list:
				t = sha256(r)
				for x in range(b.blocknumber-(b.epoch*c.blocks_per_epoch)):
					t = sha256(t)
				for s in stake_list_get():
					if t in s[1]:
						i+=1
		
			if i != len(b.reveal_list):
				printL(( 'Not all the reveal_hashes are valid..'))
				return False


	if sha256(b.stake_selector+str(b.epoch)+str(b.stake_nonce)+str(b.block_reward)+str(b.timestamp)+str(b.hash)+str(b.blocknumber)+b.prev_blockheaderhash+str(b.number_transactions)+b.merkle_root_tx_hash+str(b.number_stake)+b.hashedstake) != b.headerhash:
		printL(( 'Headerhash false for block: failed validation'))
		return False

	if m_get_block(last_block).blockheader.headerhash != block.blockheader.prev_blockheaderhash:
		printL(( 'Headerhash not in sequence: failed validation'))
		return False
	if m_get_block(last_block).blockheader.blocknumber != block.blockheader.blocknumber-1:
		printL(( 'Block numbers out of sequence: failed validation'))
		return False

	if validate_tx_in_block(block) == False:
		printL(( 'Block validate_tx_in_block error: failed validation'))
		return False

	if validate_st_in_block(block) == False:
		printL(( 'Block validate_st_in_block error: failed validation'))
		return False

	if len(block.transactions) == 0:
		txhashes = sha256('')
	else:
		txhashes = []
		for transaction in block.transactions:
			txhashes.append(transaction.txhash)

	if merkle_tx_hash(txhashes) != block.blockheader.merkle_root_tx_hash:
		printL(( 'Block hashedtransactions error: failed validation'))
		return False

	sthashes = []
	for st in block.stake:
		sthashes.append(str(st.hash))

	if sha256(''.join(sthashes)) != b.hashedstake:
		printL(( 'Block hashedstake error: failed validation'))

	if verbose==1:
		printL(( b.blocknumber, 'True'))

	return True


# simple transaction creation and wallet functions using the wallet file..

def wlt():
	return merkle.numlist(wallet.list_addresses())

def create_my_tx(txfrom, txto, amount, fee=0):
	if isinstance(txto, int):
		txto = my[txto][0]

	tx = SimpleTransaction().create_simple_transaction(txfrom=my[txfrom][0], txto=txto, amount=amount, data=my[txfrom][1], fee=fee)

	if tx and tx.state_validate_tx():
		add_tx_to_pool(tx)
		wallet.f_save_winfo()	#need to keep state after tx ..use wallet.info to store index..far faster than loading the 55mb wallet..
		return tx
	
	return False


