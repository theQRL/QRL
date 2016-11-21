#wallet code

__author__ = 'pete'

from bitcoin import sha256
import merkle
import chain
import cPickle as pickle
import node 
import os

global mywallet
mywallet = []

def log(string_data):
    with open("./log/log.txt", "a") as myfile:
        myfile.write(string_data)
    return

def f_read_wallet():

	addr_list = []

	if os.path.isfile('./wallet.dat') is False:
		print 'Creating new wallet file'
		addr_list.append(getnewaddress(196, 'WOTS'))
		with open("./wallet.dat", "a") as myfile:				#add in a new call to create random_otsmss
        		pickle.dump(addr_list, myfile)

	try:
			with open('./wallet.dat', 'r') as myfile:
				return pickle.load(myfile)
	except:
			print 'IO error'
			return False
	
def f_append_wallet(data):

		data2 = f_read_wallet()
		data2.append(data)
		if data is not False:
			print 'Appending wallet file'
			with open("./wallet.dat", "w+") as myfile:				#overwrites wallet..
        			pickle.dump(data2, myfile)
		return

def inspect_wallet():												# returns 3 lists of addresses, signatures and types..basic at present..
	data = f_read_wallet()
	if data is not False:
			num_sigs = []
			types = []
			addresses = []
			for x in range(len(data)):
				addresses.append(data[x][0])
				num_sigs.append(len(data[x][1]))
				types.append(data[x][1][0].type)
			return addresses, num_sigs, types
	return False
	
def list_addresses():
	addr = f_read_wallet()
	list_addr = []
	for address in addr:
		x=0
		y=0
		for t in chain.transaction_pool:
			if t.txfrom == address[0]:
				y+=1
				x-=t.amount

			if t.txto == address[0]:
				x+=t.amount

		#add state check for 

		list_addr.append([address[0], 'type:', address[1][0].type, 'balance: '+str(chain.state_balance(address[0]))+'('+str(chain.state_balance(address[0])+x)+')', 'nonce:'+str(chain.state_nonce(address[0]))+'('+str(chain.state_nonce(address[0])+y)+')', 'remaining signatures: '+str(address[1][0].signatures-chain.state_nonce(address[0]))+' ('+str(address[1][0].signatures-chain.state_nonce(address[0])-y)+'/'+str(address[1][0].signatures)+')' ])
	return list_addr

def getnewaddress(signatures=64, type='WOTS'):						#new address format is a list of two items [address, data structure from random_mss call]
	addr = []
	if type == 'WOTS':
		new = merkle.random_wmss(signatures=signatures)
	elif type == 'LDOTS':
		new = merkle.random_ldmss(signatures=signatures)
	else: 
		raise Exception('OTS type not recognised')

	addr.append(chain.roottoaddr(new[0].merkle_root))
	addr.append(new)

	return addr

def savenewaddress(signatures=64, type='WOTS'):
	f_append_wallet(getnewaddress(signatures, type))
