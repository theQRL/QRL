# todo prior to public testnet release

# 1)
# more sophisticated block tracking to enable chain split/fork to be identified and to ensure orphan solo chains do not appear
# try to abstract the node behaviour away from protocol to the factory whilst keeping the rules simple.
# 2)
# correct currency unit handling..need to use big int with checks rather than a float..
# 3)
# sort out the POW algo occasional errors..

__author__ = 'pete'

import time, struct, random
import chain, wallet

from twisted.internet.protocol import ServerFactory, Protocol #, ClientFactory
from twisted.internet import reactor
from merkle import sha256

cmd_list = ['balance', 'mining', 'address', 'wallet', 'send', 'getnewaddress', 'hrs', 'hrs_check', 'quit', 'exit', 'search' ,'json_search', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight', 'json_block']

api_list = ['block_data','stats', 'txhash', 'address']

def parse(data):
		return data.replace('\r\n','')

class ApiProtocol(Protocol):

	def __init__(self):
		pass

	def parse_cmd(self, data):

		data = data.split()			#typical request will be: "GET /api/{command}/{parameter} HTTP/1.1"
		if data[0] != 'GET':
			return False

		data = data[1][1:].split('/')

		if data[0].lower() != 'api':
			return False

		if data[1].lower() not in api_list:			#supported {command} in api_list
			return False
		
		my_cls = ApiProtocol()					#call the command from api_list directly
		api_call = getattr(my_cls, data[1].lower())	
		
		if len(data) < 3:
			self.transport.write(api_call())
		else:
			self.transport.write(api_call(data[2]))

		return


	def block_data(self, data=None):				# if no data = last block ([-1])			#change this to add error.. 
		error = {'status': 'Error','block_data' : data}
		print '<<< API block data call', data	
		if not data:
			return chain.json_print_telnet(chain.m_get_last_block())
		try: int(data)														# is the data actually a number?
		except: 
			return chain.json_print_telnet(error)
		js_bk = chain.json_print_telnet(chain.m_get_block(int(data)))
		if js_bk == 'false':
			return chain.json_print_telnet(error)
		else:
			return js_bk

	def stats(self, data=None):
		print '<<< API stats call'
		net_stats = {'uptime': str(time.time()-start_time), 'blockheight' : str(chain.m_blockheight()), 'nodes' : str(len(f.peers)) }
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

			elif data[0] == 'hrs':
				if not args:
					self.transport.write('>>> Human Readable String allows you to receive transactions to a user chosen text string instead of the Q-address you hold the private key for.'+'\r\n')
					self.transport.write('>>> Usage: hrs <valid wallet address number>'+'\r\n')
					self.transport.write('>>> e.g. "hrs 0 david@gmail.com" allows users from other QRL nodes to send transactions directly to david@gmail.com instead of the Q-address at wallet position 0'+'\r\n')
					return
				try: int(args[0])
				except: 
						self.transport.write('>>> Usage: hrs <wallet address number>'+'\r\n')
						return 
				if int(args[0]) > len(wallet.list_addresses())-1:
					self.transport.write('>>> Wallet number invalid. Usage: hrs <wallet address number to substitute for a human readable string>'+'\r\n')
					return

				if not args[1]:
					self.transport.write('>>> no hrs string supplied..'+'\r\n')
					return

				(tx, msg) = chain.create_hrs_tx(int(args[0]), args[1])
				if tx is not False:
					f.send_tx_to_peers(tx)
					self.transport.write('<<< HRS TX from '+args[0]+' for string: '+args[1]+' sent into network..'+'\r\n')
				else:
					self.transport.write('>>> HRS TX Failed: '+msg+'\r\n')
				return

			elif data[0] == 'hrs_check':
				if not args:
					self.transport.write('>>> Usage: hrs <human readable string>'+'\r\n')
					self.transport.write('>>> Returns the Q-address associated with the string'+'\r\n')
				hrs = chain.state_hrs(args[0])
				if hrs is not False:
					self.transport.write(hrs+'\r\n')
				else:
					self.transport.write('>>> Human readable string not found in blockchain.'+'\r\n')
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
			
			elif data[0] == 'mining':
				self.transport.write('>>> Mining set to: '+str(f.nomining)+'\r\n')
				f.nomining = not f.nomining
				print 'No-Mining flag set to: ', str(f.nomining)

			elif data[0] == 'send':
				self.send_tx(args)

			elif data[0] == 'help':
				self.transport.write('>>> QRL ledger help: try quit, wallet, send, balance, search, json_block, json_search, hrs, hrs_check, mining, getinfo, blockheight or getnewaddress'+'\r\n')

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
					self.transport.write('>>> Uptime: '+str(time.time()-start_time)+'\r\n')
					self.transport.write('>>> Nodes connected: '+str(len(f.peers))+'\r\n')

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
			self.transport.write('>>> Usage: getnewaddress <n> <type (WOTS or LDOTS)>'+'\r\n')
			self.transport.write('>>> i.e. getnewaddress 196 WOTS'+'\r\n')
			self.transport.write('>>> or: getnewaddress 128 LDOTS'+'\r\n')
			self.transport.write('>>> (new address creation can take a while, please be patient..)'+'\r\n')
			return 
		else:
			try:	int(args[0])
			except:
					self.transport.write('>>> Invalid number of signatures. Usage: getnewaddress <n signatures> <type (WOTS or LDOTS)>'+'\r\n')
					self.transport.write('>>> i.e. getnewaddress 196 WOTS'+'\r\n')
					return

		if args[1] != 'WOTS' and args[1] != 'wots' and args[1] != 'LDOTS' and args[1] != 'ldots' and args[1] != 'LD':
			self.transport.write('>>> Invalid signature address type. Usage: getnewaddress <n> <type (WOTS or LDOTS)>'+'\r\n')
			self.transport.write('>>> i.e. getnewaddress 128 LDOTS'+'\r\n')
			return

		if args[1] == 'wots':
			args[1] = 'WOTS'

		if args[1] == 'ldots' or args[1] == 'LD':
			args[1] = 'LDOTS'

		if int(args[0]) > 256:
			self.transport.write('>>> Try a lower number of signatures or you may be waiting a very long time...'+'\r\n')
			return

		self.transport.write('>>> Creating address..please wait'+'\r\n')
		addr = wallet.getnewaddress(int(args[0]), args[1])

		self.transport.write('>>> Keypair type: '+''.join(addr[1][0].type+'\r\n'))
		self.transport.write('>>> Signatures possible with address: '+str(len(addr[1]))+'\r\n')
		self.transport.write('>>> Address: '+''.join(addr[0])+'\r\n')
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
		
		balance = chain.state_balance(wallet.f_read_wallet()[int(args[0])][0])

		try: int(args[2])
		except: 
				self.transport.write('>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
				return

		if balance < int(args[2]):
				self.transport.write('>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
				return

		(tx, msg) = chain.create_my_tx(int(args[0]), args[1], int(args[2]))
		self.transport.write(msg+'\r\n')
		if tx is False:
				return
				
		#print 'new local tx: ', tx
		f.send_tx_to_peers(tx)
		self.transport.write('>>> '+str(tx.txhash))
		self.transport.write('>>> From: '+str(tx.txfrom)+' To: '+str(tx.txto)+' For: '+str(tx.amount)+'\r\n'+'>>>created and sent into p2p network'+'\r\n')
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
			self.recv_tx(suffix)
			
		elif prefix == 'BK':			#block received
			self.recv_block(suffix)

		elif prefix == 'LB':			#request for last block to be sent
				print '<<<Sending last block', str(chain.m_blockheight()), str(len(chain.json_bytestream(chain.m_get_last_block()))),' bytes', 'to node: ', self.transport.getPeer().host
				self.transport.write(self.wrap_message(chain.json_bytestream_bk(chain.m_get_last_block())))
				return

		elif prefix == 'MB':		#we send with just prefix as request..with a number as answer..
			if not suffix:
				print '<<<Sending current blockheight to node..', self.transport.getPeer().host, str(time.time())
				self.transport.write(self.wrap_message('CB'+str(chain.m_blockheight())))
			
		elif prefix == 'CB':
				print '>>>Received current latest blockheight from  node@', self.transport.getPeer().host, 'blockheight: ', suffix, 'local blockheight: ', str(chain.m_blockheight()), str(time.time())
				if int(suffix) > chain.m_blockheight():		#if blockheight of other node greater then we are not the longest chain..how many blocks behind are we?
					self.factory.sync = 0
					print 'local node behind connection by ', str(int(suffix)-chain.m_blockheight()), 'blocks - synchronising..'
					self.get_block_n(chain.m_blockheight()+1)
					return
				else:
					self.factory.sync = 1
					if self.factory.mining == 0:
						self.factory.newblock = 0
						reactor.callInThread(f.mining_fn, chain.m_get_last_block().blockheader)
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

		elif prefix == 'PI':
			if suffix[0:2] == 'NG':
				self.transport.write(self.wrap_message('PONG'))
			else:
				self.transport.loseConnection()
				return

		elif prefix == 'PL':			#receiving a list of peers to save into peer list..
				self.recv_peers(suffix)

		elif prefix == 'PE':			#get a list of connected peers..need to add some ddos and type checking proteection here..
				self.get_peers()

		else:
			print 'Data from node not understood - closing connection.'
			self.transport.loseConnection()
		
		return


	def recv_peers(self, json_data):
		data = chain.json_decode(json_data)
		new_ips = []
		for ip in data:
				new_ips.append(ip.encode('latin1'))
		peers_list = chain.state_get_peers()
		print self.transport.getPeer().host, 'peers: ', new_ips
		for node in new_ips:
				if node not in peers_list:
					if node != self.transport.getHost().host:
						peers_list.append(node)
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
		if self.transport.getPeer().host == self.transport.getHost().host:
						self.transport.loseConnection()
						return
		self.factory.connections += 1
		self.factory.peers.append(self)
		peer_list = chain.state_get_peers()
		if self.transport.getPeer().host not in peer_list:
			print 'Adding to peer_list'
			peer_list.append(self.transport.getPeer().host)
			chain.state_put_peers(peer_list)
			chain.state_save_peers()
		print '>>> new peer connection :', self.transport.getPeer().host, ' : ', str(self.transport.getPeer().port)
		

		self.get_m_blockheight_from_connection()
		self.get_peers()

		# here goes the code for handshake..using functions within the p2pprotocol class
		# should ask for latest block/block number.
		

	def connectionLost(self, reason):
		self.factory.connections -= 1
		print self.transport.getPeer().host,  ' disconnnected. ', 'remainder connected: ', str(self.factory.connections) #, reason 
		self.factory.peers.remove(self)

	def recv_block(self, json_block_obj):
		try: block = chain.json_decode_block(json_block_obj)
		except:
				print 'block rejected - unable to decode serialised data - closing connection to -', self.transport.getPeer().host
				self.transport.loseConnection()
				return

		for b in chain.m_blockchain[-5:-1]:	#non functional
			if block.blockheader.headerhash == b.blockheader.headerhash:
				print '>>>BLOCK - already received - ', str(block.blockheader.blocknumber), block.blockheader.headerhash
				return

		if block.blockheader.blocknumber != chain.m_blockheight()+1:
			print '>>>BLOCK - out of order - need', str(chain.m_blockheight()+1), ' received ', str(block.blockheader.blocknumber), block.blockheader.headerhash, ' from ', self.transport.getPeer().host
			return

		print '>>>BLOCK - ', block.blockheader.headerhash, str(block.blockheader.blocknumber), block.blockheader.timestamp, str(len(json_block_obj)), 'bytes - ', self.transport.getPeer().host
		
		if chain.m_add_block(block) is True:
				self.factory.newblock = 1
								#new valid block detected..need to inform the mining thread 
				#print 'sync', str(self.factory.sync), 'mining', str(self.factory.mining), 'newblock', str(self.factory.newblock)

				if self.factory.sync == 1:						
					for peer in self.factory.peers:
						if peer != self:
							peer.transport.write(self.wrap_message(chain.json_bytestream_bk(block)))
				self.get_m_blockheight_from_connection()	
				return
		else:
				#print 'BAD BLOCK:', block.blockheader.headerhash, block.blockheader.blocknumber, ' invalid and discarded -', self.transport.getPeer().host
				self.get_m_blockheight_from_connection()
				return

	def recv_tx(self, json_tx_obj):
		try: tx = chain.json_decode_tx(json_tx_obj)
		except: 
				print 'tx rejected - unable to decode serialised data - closing connection'
				self.transport.loseConnection()
				return

		for t in chain.transaction_pool:			#duplicate tx already received, would mess up nonce..
			if tx.txhash == t.txhash:
				return

		if chain.validate_tx(tx) == True:
				chain.add_tx_to_pool(tx)

		if chain.state_validate_tx(tx) == True:
				print '>>>TX - ', tx.txhash, ' from - ', self.transport.getPeer().host, ' relaying..'
				
				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message(chain.json_bytestream_tx(tx)))
		else:
				chain.remove_tx_from_pool(tx)
				print '>>>TX',tx.txhash, ' invalid - closing connection to ', self.transport.getPeer().host
				self.transport.loseConnection()
		return


class p2pFactory(ServerFactory):

	protocol = p2pProtocol

	def __init__(self):
		self.nomining = True			#default to mining off as the wallet functions are not that responsive at present with it enabled..
		self.peers = []
		self.connections = 0
		self.buffer = ''
		self.sync = 0
		self.mining = 0
		self.newblock = 0
		self.exit = 0

# mining

	def mining_fn(self, block_obj_header):
		
		self.mining = 1			#to prevent other protocol instances launching the function..
		while True:
				if self.nomining == True:
					print 'Mining disabled (telnet into localhost:2000 and type "mining" to switch mining to active'
				else:
					print 'Mining for next block..'
				
				z = 0

				for x in range(600):
					if self.nomining == True:
						time.sleep(1)
						pass
					else:

						h_hash = block_obj_header.headerhash
						diff = 2**block_obj_header.difficulty
						
						y = random.randint(0,2**255)
						for x in range(y,y+1000000):
							z+=1
							if int(sha256(h_hash+str(x)),16) < diff:
								print '>>>MINED block in ',str(z), 'attempts, at diff 2**', str(block_obj_header.difficulty)

								if self.sync == 1:
									b = chain.m_create_block(str(x))
									#chain.json_print(b)
									print chain.validate_block(b)
									print 'time between blocks= '+str(b.blockheader.timestamp-block_obj_header.timestamp)
									if chain.m_add_block(b) == True:	
										reactor.callFromThread(f.send_block_to_peers, b)
										self.mining = 0
										self.newblock = 0
										for peer in self.peers:
											reactor.callFromThread(peer.get_m_blockheight_from_connection)
										print 'Mining cycle finished. 2', str(time.time())
										return

					if self.newblock == 1:
						print 'Mining cycle finished..3'
						self.mining = 0
						self.newblock = 0
						for peer in self.peers:
							reactor.callFromThread(peer.get_m_blockheight_from_connection)
						return

					if not self.peers:
						self.mining = 0
						self.newblock = 0
						print 'Mining cyle finished..without creating block - no connected peers 4'
						return



# factory network functions

	def f_wrap_message(self, data):
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(data))+chr(0)+data+chr(0)+chr(0)+chr(255)

	def send_tx_to_peers(self, tx):
		print '<<<Transmitting TX: ', tx.txhash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message(chain.json_bytestream_tx(tx)))
		return

	def send_block_to_peers(self, block):
		print '<<<Transmitting block: ', block.blockheader.headerhash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message(chain.json_bytestream_bk(block)))
		return

# connection functions

	def connect_peers(self):
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
		pass

if __name__ == "__main__":
 
	start_time = time.time()
	print 'QRL blockchain ledger v 0.01'

	print 'Reading chain..'
	chain.m_load_chain()
	print str(len(chain.m_blockchain))+' blocks'
	print 'Verifying chain' 
	chain.m_verify_chain(verbose=1)
	print 'Building state leveldb'
	chain.state_read_chain()
	
	print 'Loading node list..'			# load the peers for connection based upon previous history..
	chain.state_load_peers()
	print chain.state_get_peers()

	stuff = 'QRL node connection established. Try starting with "help"'+'\r\n'
	print '>>>Listening..'
	
	f = p2pFactory()
	api = ApiFactory()

	reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
	reactor.listenTCP(9000, f)
	reactor.listenTCP(80, api)

	print '<<<Connecting to nodes in peer.dat'

	f.connect_peers()
	reactor.run()
	    