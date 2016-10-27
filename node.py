# need to write txt via a buffer function instead of line by line..

__author__ = 'pete'

import chain
import sys
import time
import wallet

from twisted.internet.protocol import ServerFactory, Protocol, ClientFactory
from twisted.internet import reactor

global p2p_list
p2p_list = []

node_list = [('127.0.0.1', 9000),('127.0.0.1', 9001)]

cmd_list = ['balance', 'address', 'wallet', 'send', 'getnewaddress', 'quit', 'exit', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight', 'send']

def parse(data):
		return data.replace('\r\n','')



class WalletProtocol(Protocol):

	def __init__(self):		#way of passing data back to parent factory - use self.factory.whatever
		pass
		

	def parse_cmd(self, data):

		data = data.split()
		args = data[1:]
		print data[0], data, args


		if data[0] in cmd_list:			#can nest a further 'for word in data' or split data into a list and use data[0] to allow args..
			pass
			#self.transport.write('Command: '+data+'\r\n')

			if data[0] == 'getnewaddress':
				addr = wallet.getnewaddress(4)
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

				print str(int(args[2]))

				if balance < int(args[2]):
					self.transport.write('Invalid amount to send. Type a number less than or equal to the balance of the sending address'+'\r\n')
					return

				tx = chain.create_my_tx(int(args[0]), args[1], int(args[2]))
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

	def __init__(self):		#way of passing data back to parent factory - use self.factory.whatever
		pass

	def parse_cmd(self, data):

		if data in cmd_list:
			pass
			self.transport.write('Command: '+data+'\r\n')

			if data == 'getnewaddress':
				pass
			elif data == 'quit' or data == 'exit':
				self.transport.loseConnection()
		else:
			return False

		return True


	def dataReceived(self, data):
		sys.stdout.write('.')
		sys.stdout.flush()
		self.factory.recn += 1
		if self.parse_cmd(parse(data)) == False:
			self.transport.write('Command not recognised. Use help for details'+'\r\n')
	
		

	def connectionMade(self):
		self.transport.write(self.factory.stuff)
		self.factory.connections += 1
		print '** new p2p connection', str(self.factory.connections)

	def connectionLost(self, reason):
		print 'lost connection'
		self.factory.connections -= 1

	#def nodeConnect(self, host, port, factory=p2pCliFactory):
	#	reactor.connectTCP(host, port, factory)

class p2pCliFactory(ClientFactory):
	protocol = p2pProtocol


class p2pFactory(ServerFactory):

	protocol = p2pProtocol

	def __init__(self, stuff):
		self.stuff = stuff
		self.recn = 0
		self.connections = 0

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
	

	stuff = 'QRL node connection established.'+'\r\n'
	port = reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
	port2 = reactor.listenTCP(9000, p2pFactory(stuff))

	print port.getHost()
	print port2.getHost()
	

	reactor.run()
