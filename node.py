# QRL testnet node..
# -features POS, quantum secure signature scheme..


__author__ = 'pete'

import time, struct, random, copy, decimal
import chain, wallet

from twisted.internet.protocol import ServerFactory, Protocol 
from twisted.internet import reactor
from merkle import sha256, numlist, hexseed_to_seed, mnemonic_to_seed, GEN_range
from operator import itemgetter
from collections import Counter
from math import ceil

version_number = "alpha/0.02"

cmd_list = ['balance', 'mining', 'seed', 'hexseed', 'recoverfromhexseed', 'recoverfromwords', 'stakenextepoch', 'stake', 'address', 'wallet', 'send', 'mempool', 'getnewaddress', 'quit', 'exit', 'search' ,'json_search', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight', 'json_block']
api_list = ['block_data','stats', 'txhash', 'address', 'empty', 'last_tx', 'stake_reveal_ones', 'last_block', 'richlist', 'ping', 'stake_commits', 'stake_reveals', 'stake_list', 'stakers', 'next_stakers']


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
			reactor.callLater(30, reveal_two_logic)
									
	else:
		print 'await block creation by stake validator:', chain.stake_list[chain.epoch_prf[1]][0]
		#f.send_st_to_peers(data)
	return

# we end up here exactly 15 seconds after the last block arrived or was created and sent out..

def reveal_two_logic(data=None):
	print 'reveal_two_logic'

	reveals = []

	for s in chain.stake_reveal_one:
		if s[1] == chain.m_blockchain[-1].blockheader.headerhash and s[2] == chain.m_blockchain[-1].blockheader.blocknumber+1:
			reveals.append(s[3])

	#print 'numlist reveals:'
	#numlist (reveals)

	# what is the PRF output for this block?	

	winner = chain.cl_hex(chain.epoch_PRF[chain.m_blockchain[-1].blockheader.blocknumber+1], reveals)

	for s in chain.stake_reveal_one:
		if s[3] == winner:
			winning_staker = s[0]
		if s[0] == chain.mining_address:
			our_reveal = s[3]

	print 'chain.epoch_PRF: ', chain.epoch_PRF[chain.m_blockchain[-1].blockheader.blocknumber+1]
	print 'win reveal: ', winner, 'of:', str(len(reveals)), 'stake validator: ', winning_staker, 'b :', chain.m_blockchain[-1].blockheader.blocknumber+1
	
	if winner == our_reveal:
		print 'BLOCK SELECTOR'
		print 'reveals', reveals
		reveal_three_logic(winner, reveals)
		return


def reveal_three_logic(winner, reveals):

	# code to create the block..

	tx_list = []
	for t in chain.transaction_pool:
		tx_list.append(t.txhash)
	block_obj = chain.create_stake_block(tx_list, winner, reveals)

	if chain.m_add_block(block_obj) == True:
			f.send_block_to_peers(block_obj)

	else: 
		print 'reveal_three_logic: bad block'
		return

	try: reactor.callIDR15.cancel()		#shouldnt see this really..
	except:	pass								
	try: reactor.callID2.cancel()		#cancel the soon to be re-called missed block logic..
	except: pass

	if f.stake == True:									# we are staking and synchronised -> are we in the next staker list?
		x=0
		for s in chain.next_stake_list_get():
			if s[0] == chain.mining_address:
				x=1													#already in the next_stake_list..
		if x==0:
			print 'STAKE adding to next_stake_list'
			f.send_st_to_peers(chain.CreateStakeTransaction())
		else:
			print 'STAKE already in next epoch'

		for s in chain.stake_list_get():								
			if chain.mining_address == s[0]:	
				print 'STAKE this epoch with, ', chain.mining_address
				f.send_stake_reveal_one()
				reactor.callIDR15 = reactor.callLater(30, reveal_two_logic)
				reactor.callID2 = reactor.callLater(60, pos_missed_block)
	return


def pos_missed_block(data=None):
	print '** Missed block logic ** - trigger m_blockheight recheck..'
	f.missed_block=1
	f.get_m_blockheight_from_peers()
	return



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

			elif data[0] == 'balance':
				self.getbalance(args)

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

		elif prefix == 'BK':			#block received
			self.recv_block(suffix)

		elif prefix == 'LB':			#request for last block to be sent
				print '<<<Sending last block', str(chain.m_blockheight()), str(len(chain.json_bytestream(chain.m_get_last_block()))),' bytes', 'to node: ', self.transport.getPeer().host
				self.transport.write(self.wrap_message(chain.json_bytestream_bk(chain.m_get_last_block())))
				return

		elif prefix == 'MB':		#we send with just prefix as request..with a number as answer..
			if not suffix:
				print '<<<Sending blockheight to:', self.transport.getPeer().host, str(time.time())
				self.transport.write(self.wrap_message('CB'+str(chain.m_blockheight())))
			
		elif prefix == 'CB':
				print '>>>Blockheight from:', self.transport.getPeer().host, 'blockheight: ', suffix, 'local blockheight: ', str(chain.m_blockheight()), str(time.time())
				if int(suffix) > chain.m_blockheight():		#if blockheight of other node greater then we are not the longest chain..how many blocks behind are we?
					self.factory.sync = 0
					print 'local node behind connection by ', str(int(suffix)-chain.m_blockheight()), 'blocks - synchronising..'
					self.get_block_n(chain.m_blockheight()+1)
					return
				else:
					self.factory.sync = 1
					# this is where the POS algorithm starts..

					# 1. check the block height is 0.

					if len(chain.m_blockchain) == 1 and self.factory.genesis == 0:
						self.factory.genesis = 1										# set the flag so that no other Protocol instances trigger the genesis stake functions..
						print 'genesis pos countdown to block 1 begun, 60s until stake tx circulated..'
						reactor.callLater(1, pre_pos_1)
						return
					elif len(chain.m_blockchain) == 1 and self.factory.genesis == 1:
						return

					# 2. restart the network if it has paused

					if chain.m_blockchain[-1].blockheader.timestamp < time.time()-110:
						if self.factory.missed_block == 0:
							reactor.callID2 = reactor.callLater(60, pos_missed_block)		# block should be here by now..begin redundancy logic
							return
						else:
						 del chain.stake_reveal_one[:]						
						 for s in chain.stake_list_get():
							if chain.mining_address == s[0]:
								print 'Restart network and STAKE this epoch with, ', chain.mining_address
								f.send_stake_reveal_one()
								reactor.callIDR15 = reactor.callLater(30, reveal_two_logic)
								self.factory.missed_block=0
								return

					return

		elif prefix == 'BN':			#request for block (n)
				if int(suffix) <= chain.m_blockheight():
						print '<<<Sending block number', str(int(suffix)), str(len(chain.json_bytestream(chain.m_get_block(int(suffix))))),' bytes', 'to node: ', self.transport.getPeer().host
						self.transport.write(self.wrap_message(chain.json_bytestream_bk(chain.m_get_block(int(suffix)))))
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

				chain.stake_reveal_one.append([stake_address, headerhash, block_number, reveal_one]) #merkle_hash_tx, commit_hash])

				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message('R1'+chain.json_encode(z)))	#relay
				return


		
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
		if not self.buffer:
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

		self.parse_buffer()				# need a way of iterating through the parse_buffer better..functional..
		self.parse_buffer()
		self.parse_buffer()
		
		for msg in self.messages:
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
			reactor.callLater(120,f.connect_peers)

	def recv_block(self, json_block_obj):
		

		try: block = chain.json_decode_block(json_block_obj)
		except:
				print 'block rejected - unable to decode serialised data - closing connection to -', self.transport.getPeer().host
				#self.transport.loseConnection()
				return

		if block.blockheader.headerhash == chain.m_blockchain[-1].blockheader.headerhash:
				#print '>>>BLOCK - already received - ', str(block.blockheader.blocknumber), block.blockheader.headerhash
				return

		if block.blockheader.blocknumber != chain.m_blockheight()+1:
			print '>>>BLOCK - out of order - need', str(chain.m_blockheight()+1), ' received ', str(block.blockheader.blocknumber), block.blockheader.headerhash, ' from ', self.transport.getPeer().host
			return

		print '>>>BLOCK - ', block.blockheader.headerhash, str(block.blockheader.blocknumber), block.blockheader.timestamp, str(len(json_block_obj)), 'bytes - ', self.transport.getPeer().host
		
		if chain.m_add_block(block) is True:
				
				print 'reveals:', block.blockheader.reveal_list

				if self.factory.sync == 1:

					for peer in self.factory.peers:
						if peer != self:
							peer.transport.write(self.wrap_message(chain.json_bytestream_bk(block)))
				
				#self.get_m_blockheight_from_connection()	
				
				if self.factory.sync == 1:

										try:	reactor.callIDR15.cancel()	#shouldnt see this really..
										except:	pass
										
										try:	reactor.callID.cancel()		#cancel the ST genesis loop if still running..
										except: pass
										try: 	reactor.callID2.cancel()		#cancel the soon to be re-called missed block logic..
										except: pass

										reactor.callID2 = reactor.callLater(120, pos_missed_block)		# block should be here by now..begin redundancy logic
										
										if self.factory.stake == True:									# we are staking and synchronised -> are we in the next staker list?
											x=0
											for s in chain.next_stake_list_get():
												if s[0] == chain.mining_address:
													x=1													#already in the next_stake_list..
											if x==0:
												print 'STAKE adding to next_stake_list'
												f.send_st_to_peers(chain.CreateStakeTransaction())
											else:
												print 'STAKE already in next epoch'
										
											for s in chain.stake_list_get():
												if chain.mining_address == s[0]:
													print 'STAKE this epoch with, ', chain.mining_address
													f.send_stake_reveal_one()
													reactor.callIDR15 = reactor.callLater(30, reveal_two_logic)
													return
											
				else:
					print '**POS commit later 30 (recv block)** - not called as not SYNC'
					self.get_m_blockheight_from_connection()
				return
		else:
				#print 'BAD BLOCK:', block.blockheader.headerhash, block.blockheader.blocknumber, ' invalid and discarded -', self.transport.getPeer().host
				self.get_m_blockheight_from_connection()
				return

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
		self.mining = 0
		self.newblock = 0
		self.exit = 0
		self.genesis = 0
		self.missed_block = 0


# factory network functions
	def get_m_blockheight_from_peers(self):
		for peer in self.peers:
			peer.get_m_blockheight_from_connection()

	def f_wrap_message(self, data):
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(data))+chr(0)+data+chr(0)+chr(0)+chr(255)

	def send_st_to_peers(self, st):
		print '<<<Transmitting ST:', st.hash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('ST'+chain.json_bytestream(st)))

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
	
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message('R1'+chain.json_encode(z)))
		
		chain.stake_reveal_one.append([z['stake_address'],z['headerhash'], z['block_number'], z['reveal_one']])		#don't forget to store our reveal in stake_reveal_one
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
	print 'QRL blockchain ledger v 0.01'

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
	    