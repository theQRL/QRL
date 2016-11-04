# todo
# work out a way to get from tx create in walletfactory to tx/block transmission through p2pfactory
# need to setup a new factory which will call the POW library py


__author__ = 'pete'

import os
import chain
import sys
import struct
import time
import wallet
import pickle
from twisted.internet.protocol import ServerFactory, Protocol #, ClientFactory
from twisted.internet import reactor

cmd_list = ['balance', 'address', 'wallet', 'send', 'getnewaddress', 'quit', 'exit', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight', 'send']

def parse(data):
		return data.replace('\r\n','')



class WalletProtocol(Protocol):

	def __init__(self):		
		pass
		

	def parse_cmd(self, data):

		data = data.split()
		args = data[1:]


		if data[0] in cmd_list:			

			if data[0] == 'getnewaddress':

				if not args or len(args) > 2:
					self.transport.write('Arguments not recognised. Creating a 128 signature WOTS-MSS address. Please wait.'+'\r\n')
					addr = wallet.getnewaddress(128,'WOTS')
				
				else:
					try:	int(args[0])
					except:
							self.transport.write('Invalid number of signatures. Usage: getnewaddress <n> <type (WOTS or LDOTS)>'+'\r\n')
							self.transport.write('>>> i.e. getnewaddress 196 WOTS'+'\r\n')
							return

					if args[1] != 'WOTS' or args[1] != 'wots' or args[1] != 'LDOTS' or args[1] != 'ldots' or args[1] != 'LD':
						self.transport.write('Invalid signature address type. Usage: getnewaddress <n> <type (WOTS or LDOTS)>'+'\r\n')
						self.transport.write('>>> i.e. getnewaddress 128 LDOTS'+'\r\n')
						return

					if int(args[0]) > 256:
						self.transport.write('Try a lower number of signatures or you may be waiting a very long time...'+'\r\n')
						return

					addr = wallet.getnewaddress(int(args[0], args[1]))


				self.transport.write('Keypair type: '+''.join(addr[1][0].type+'\r\n'))
				self.transport.write('Signatures possible with address: '+str(len(addr[1]))+'\r\n')
				self.transport.write('Address: '+''.join(addr[0])+'\r\n')
				self.transport.write("type 'savenewaddress' to append to wallet file"+'\r\n')
				self.factory.newaddress = addr

			elif data[0] == 'savenewaddress':
				if not self.factory.newaddress:
					print 'no new addresses, yet'
					self.transport.write("No new addresses created, yet. Try 'getnewaddress'"+'\r\n')
					return
				wallet.f_append_wallet(self.factory.newaddress)
				print 'writing wallet'

		

			elif data[0] == 'send':
				if not args or len(args) < 3:
					self.transport.write('Usage: send <from> <to> <amount>'+'\r\n')
					self.transport.write('i.e. send 0 4 100'+'\r\n')
					self.transport.write('^ will send 100 coins from address 0 to 4 from the wallet'+'\r\n')
					self.transport.write('<to> can be a pasted address (starts with Q)'+'\r\n')
					return

				try: int(args[0])
				except: 
					self.transport.write('Invalid sending address. Try a valid number from your wallet - type wallet for details.'+'\r\n')
					return
				if int(args[0]) > len(wallet.list_addresses())-1:
					self.transport.write('Invalid sending address. Try a valid number from your wallet - type wallet for details.'+'\r\n')
					return

				if args[1][0] == 'Q':
					pass
				else:
					try: int(args[1])
					except:
						self.transport.write('Invalid receiving address - addresses must start with Q. Try a number your wallet.'+'\r\n')
						return
					if int(args[1]) > len(wallet.list_addresses())-1:
						self.transport.write('Invalid receiving address - addresses must start with Q. Try a number your wallet.'+'\r\n')
						return
					args[1] = int(args[1])
				balance = chain.state_balance(wallet.f_read_wallet()[int(args[0])][0])

				try: int(args[2])
				except: 
					self.transport.write('Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
					return

				if balance < int(args[2]):
					self.transport.write('Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
					return

				tx = chain.create_my_tx(int(args[0]), args[1], int(args[2]))
				if tx is False:
					self.transport.write('transaction creation failed..'+'\r\n')
					return
				
				print 'new local tx: ', tx
				f.send_tx_to_peers(tx)
				self.transport.write(str(tx)+'\r\n')
				self.transport.write('From: '+str(tx.txfrom)+'\r\n'+'To: '+str(tx.txto)+'\r\n'+'For: '+str(tx.amount)+'\r\n'+'>>>created and sent into p2p network'+'\r\n')
				
				return

			

			elif data[0] == 'help':
				self.transport.write('QRL ledger help: try quit, wallet, send or getnewaddress'+'\r\n')

			elif data[0] == 'quit' or data == 'exit':
				self.transport.loseConnection()

			elif data[0] == 'listaddresses':
					addresses, num_sigs, types = wallet.inspect_wallet()
					
					for x in range(len(addresses)):
						self.transport.write(str(x)+', '+addresses[x]+'\r\n')

			elif data[0] == 'wallet':
					if chain.state_uptodate() == False:
						chain.state_read_chain()
					self.transport.write('Wallet contents:'+'\r\n')
					y=0
					for address in wallet.list_addresses():
						self.transport.write(str(y)+str(address)+'\r\n')
						y+=1
					
			elif data[0] == 'getinfo':
					self.transport.write('Uptime: '+str(time.time()-start_time)+'\r\n')

			elif data[0] == 'blockheight':
					self.transport.write('Blockheight: '+str(chain.m_blockheight())+'\r\n')
		else:
			return False

		return True


	def dataReceived(self, data):
		sys.stdout.write('.')
		sys.stdout.flush()
		self.factory.recn += 1
		if self.parse_cmd(parse(data)) == False:
			self.transport.write("Command not recognised. Use 'help' for details"+'\r\n')
	
		

	def connectionMade(self):
		self.transport.write(self.factory.stuff)
		self.factory.connections += 1
		if self.factory.connections > 1:
			print 'only one local connection allowed'
			self.transport.write('only one local connection allowed, sorry')
			self.transport.loseConnection()
		else:
			if self.transport.getPeer().host == '127.0.0.1':
				print '** new local connection', str(self.factory.connections)
				print "connection from", self.transport.getPeer()
			else:
				self.transport.loseConnection()
				print 'Unauthorised remote login attempt.'

	def connectionLost(self, reason):
		print 'lost connection'
		self.factory.connections -= 1

class p2pProtocol(Protocol):

	def __init__(self):		
		self.buffer = ''
		self.messages = []
		pass

	def parse_msg(self, data):
		prefix = data[0:2]
		#data = data[2:]			#not sure why this isnt working..
		suffix = data[2:]
		


		if prefix == 'TX':				#tx received..
			
			try: tx = pickle.loads(suffix)
			except: 
				print 'tx rejected - unable to decode serialised data - closing connection'
				self.transport.loseConnection()
				return

			if chain.validate_tx(tx) == True and chain.state_validate_tx(tx) == True:
				print 'Validated tx received and added to pool: ', tx, 'from: ', self.transport.getPeer().host

				chain.add_tx_to_pool(tx)

				for peer in self.factory.peers:
					print 'Sending tx: ', tx, 'to other connected nodes than originator..'
					if peer != self:
						peer.transport.write(self.wrap_message(chain.tx_bytestream(tx)))
			else:
				print 'Tx invalid - closing connection'
				self.transport.loseConnection()
			return	


		elif prefix == 'BK':			#block received
			
			try: block = pickle.loads(suffix)
			except:
				print 'block rejected - unable to decode serialised data - closing connection'
				self.transport.loseConnection()
				return

			print 'block received: ', block.blockheader.headerhash, 'timestamp: ', block.blockheader.timestamp


			if chain.m_add_block(block) is True:										#crude..should check blocknumber instead..
				print 'received block added to chain and tx in pool pruned'
				
				print 'transmitting block to connected peers..'
				for peer in self.factory.peers:
					if peer != self:
						peer.transport.write(self.wrap_message(chain.bk_bytestream(block)))
				self.get_m_blockheight_from_connection()
				return
			else:
				print 'block:', block, block.blockheader.blocknumber, ' received invalid and discarded'
				self.get_m_blockheight_from_connection()
				return

		elif prefix == 'LB':			#request for last block to be sent
				print 'Sending last block', str(chain.m_blockheight()), str(len(chain.bytestream(chain.m_get_last_block()))),' bytes', 'to node: ', self.transport.getPeer().host
				self.transport.write(self.wrap_message(chain.bk_bytestream(chain.m_get_last_block())))
				return

		elif prefix == 'MB':		#we send with just prefix as request..with a number as answer..
			if not suffix:
				print 'Sending current blockheight to node..', self.transport.getPeer().host
				self.transport.write(self.wrap_message('CB'+str(chain.m_blockheight())))
			
		elif prefix == 'CB':
				print 'Received current latest blockheight from  node@', self.transport.getPeer().host, 'blockheight: ', suffix, 'local blockheight: ', str(chain.m_blockheight())
				if int(suffix) > chain.m_blockheight():		#if blockheight of other node greater then we are not the longest chain..how many blocks behind are we?
					print 'local node behind connection by ', str(int(suffix)-chain.m_blockheight()), 'blocks - synchronising..'
					
					self.get_block_n(chain.m_blockheight()+1)
					return

					

		elif prefix == 'BN':			#request for block (n)
				if int(suffix) <= chain.m_blockheight():
						print 'Sending block number', str(int(suffix)), str(len(chain.bytestream(chain.m_get_block(int(suffix))))),' bytes', 'to node: ', self.transport.getPeer().host
						self.transport.write(self.wrap_message(chain.bk_bytestream(chain.m_get_block(int(suffix)))))
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
			print 'Received peers'
			data = pickle.loads(suffix)
			peers_list = chain.state_get_peers()
			for node in data:
				if node not in peers_list:
					peers_list.append(node)
			chain.state_put_peers(peers_list)
			chain.state_save_peers()

		elif prefix == 'PE':			#get a list of connected peers..
			if suffix[0:3] == 'ERS':
				print 'Get peers request - sending active inbound connections..'
				peers_list = []
				for peer in self.factory.peers:
					peers_list.append(peer.transport.getPeer().host)
				self.transport.write(self.wrap_message('PL'+chain.bytestream(peers_list)))

		else:
			print 'Data from node not understood - closing connection.'
			self.transport.loseConnection()
		
		return

	def get_latest_block_from_connection(self):
		print 'Requested last block from', self.transport.getPeer().host
		self.transport.write(self.wrap_message('LB'))
		return

	def get_m_blockheight_from_connection(self):
		print 'Requesting blockheight from', self.transport.getPeer().host
		self.transport.write(self.wrap_message('MB'))
		return

	def get_block_n(self, n):
		print 'Requested block: ', str(n), 'from ', self.transport.getPeer().host
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
		if self.transport.getPeer().host not in peer_list:
			print 'Adding to peer_list'
			peer_list.append(self.transport.getPeer().host)
			chain.state_put_peers(peer_list)
			chain.state_save_peers()
		print '>>> new peer connection :', self.transport.getPeer().host, ' : ', str(self.transport.getPeer().port)

		self.get_m_blockheight_from_connection()

		# here goes the code for handshake..using functions within the p2pprotocol class
		# should ask for latest block/block number..

	def connectionLost(self, reason):
		self.factory.connections -= 1
		print self.transport.getPeer().host,  ' disconnnected: ', reason 
		print 'Remaining connections: ', str(self.factory.connections)
		self.factory.peers.remove(self)


class p2pFactory(ServerFactory):

	protocol = p2pProtocol

	def __init__(self):
		self.peers = []
		self.connections = 0
		self.buffer = ''
		self.synchronised = 0

	def f_wrap_message(self, data):
		return chr(255)+chr(0)+chr(0)+struct.pack('>L', len(data))+chr(0)+data+chr(0)+chr(0)+chr(255)

	def send_tx_to_peers(self, tx):
		print 'Transmitting tx: ', tx, tx.txhash
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message(chain.tx_bytestream(tx)))
		return

	def send_block_to_peers(self, block):
		print 'Transmitting block: ', block
		for peer in self.peers:
			peer.transport.write(self.f_wrap_message(chain.bk_bytestream(block)))
		return

	def clientConnectionLost(self, connector, reason):		#try and reconnect
		#print 'connection lost: ', reason, 'trying reconnect'
		connector.connect()
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

if __name__ == "__main__":

	start_time = time.time()
	print 'QRL blockchain ledger v 0.00'

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

	stuff = 'QRL node connection established.'+'\r\n'
	print 'Listening..'
	
	f = p2pFactory()

	port = reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
	#port2 = reactor.listenTCP(9000, p2pFactory())

	reactor.listenTCP(9000, f)

	#print port.getHost()
	#print port2.getHost()
	
	print 'Connecting to nodes in peer.dat'

	for peer in chain.state_get_peers():
		#reactor.connectTCP(peer, 9000, p2pFactory())
		reactor.connectTCP(peer, 9000, f)
	reactor.run()
	    