__author__ = 'pete'

import sys
import time
import wallet
import chain

from twisted.internet.protocol import ServerFactory, Protocol, ClientFactory
from twisted.internet import reactor

node_list = [('127.0.0.1', 9000),('127.0.0.1', 9001)]

cmd_list = ['balance', 'address', 'wallet', 'send', 'getnewaddress', 'quit', 'exit', 'help', 'savenewaddress', 'listaddresses','getinfo','blockheight']

def parse(data):
		return data.replace('\r\n','')



class WalletProtocol(Protocol):

	def __init__(self):		#way of passing data back to parent factory - use self.factory.whatever
		pass
		

	def parse_cmd(self, data):

		if data in cmd_list:
			pass
			#self.transport.write('Command: '+data+'\r\n')

			if data == 'getnewaddress':
				addr = wallet.getnewaddress(4)
				self.transport.write('Keypair type: '+''.join(addr[1][0].type+'\r\n'))
				self.transport.write('Signatures possible with address: '+str(len(addr[1]))+'\r\n')
				self.transport.write('Address: '+''.join(addr[0])+'\r\n')
				self.transport.write("type 'savenewaddress' to append to wallet file"+'\r\n')
				self.factory.newaddress = addr

			if data == 'savenewaddress':
				if not self.factory.newaddress:
					print 'no new addresses, yet'
					self.transport.write("No new addresses created, yet. Try 'getnewaddress'"+'\r\n')
					return
				wallet.f_append_wallet(self.factory.newaddress)
				print 'writing wallet'

			elif data == 'help':
				self.transport.write('QRL ledger help: try quit, balance, wallet, send or getnewaddress'+'\r\n')

			elif data == 'quit' or data == 'exit':
				self.transport.loseConnection()

			elif data == 'listaddresses':
					addresses, num_sigs, types = wallet.inspect_wallet()
					
					for x in range(len(addresses)):
						self.transport.write(str(x)+', '+addresses[x]+'\r\n')

			elif data == 'wallet':
					addresses, num_sigs, types = wallet.inspect_wallet()
					
					self.transport.write('Wallet contents:'+'\r\n')
					
					for x in range(len(addresses)):
						self.transport.write(str(x)+': type '+types[x]+', signatures possible: '+str(num_sigs[x])+'\r\n')
						self.transport.write('Address: '+addresses[x]+'\r\n')
			elif data == 'getinfo':
					self.transport.write('Uptime: '+str(time.time()-start_time)+'\r\n')

			elif data == 'blockheight':
					self.transport.write('Blockheight: '+str(chain.f_get_last_block().blockheader.blocknumber)+'\r\n')
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
			print '** new local connection', str(self.factory.connections)

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
	chain.f_read_chain()
	print str(chain.inspect_chain())+' blockheight'


	stuff = 'QRL node connection established.'+'\r\n'
	port = reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
	port2 = reactor.listenTCP(9000, p2pFactory(stuff))

	print port.getHost()
	print port2.getHost()
	

	reactor.run()
