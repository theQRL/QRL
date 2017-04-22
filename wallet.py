#wallet code

__author__ = 'pete'

from merkle import sha256
import merkle
import chain
import cPickle as pickle
import node 
import os
from colorama import init
from blessings import Terminal

init()

def log(string_data):
    with open("./log/log.txt", "a") as myfile:
        myfile.write(string_data)
    return

def f_read_wallet():

	addr_list = []

	term = Terminal()

	if os.path.isfile('./wallet.dat') is False:
		printL(( term.green + '[info] ' + term.normal + 'Creating new wallet file..this could take up to a minute'))
		addr_list.append(getnewaddress(4096, 'XMSS'))
		with open("./wallet.dat", "a") as myfile:				#add in a new call to create random_otsmss
        		pickle.dump(addr_list, myfile)

	try:
			with open('./wallet.dat', 'r') as myfile:
				return pickle.load(myfile)
	except:
			printL(( 'IO error'))
			return False

def f_save_wallet():
			printL(( 'Syncing wallet file'))
			with open("./wallet.dat", "w+") as myfile:				#overwrites wallet..should add some form of backup to this..seed
        			pickle.dump(chain.my, myfile)
        			return

def f_save_winfo():
			data = []
			for tree in chain.my:
				if type(tree[1])== list:
					pass
				else:
					if tree[1].type == 'XMSS':
						data.append([tree[1].mnemonic, tree[1].hexSEED, tree[1].signatures, tree[1].index, tree[1].remaining])
			printL(( 'Fast saving wallet recovery details to wallet.info..'))
			with open("./wallet.info", "w+") as myfile:				#stores the recovery phrase, signatures and the index for each tree in the wallet..
        			pickle.dump(data, myfile)
        			return



def f_load_winfo():
		try:
			with open('./wallet.info', 'r') as myfile:
				data = pickle.load(myfile)
		except:
				printL(( 'Error: likely no wallet.info found, creating..'))
				f_save_winfo()
				return False
		x = 0
		for tree in chain.my:
			if type(tree[1]) == list:						#if any part of chain.my which has loaded from f_read_wallet() on startup is lower than winfo then don't load..
				pass
			else:
				if tree[1].index <= data[x][3]:
					tree[1].index = data[x][3]		#update chain.my from winfo then save to main file..
					tree[1].remaining = data[x][4]
				else:
					return False
				x+=1
		f_save_wallet()
		return True


def f_append_wallet(data):
		if not chain.my:
			chain.my = f_read_wallet()
		if data is not False:
			chain.my.append(data)
			printL(( 'Appending wallet file..'))
			with open("./wallet.dat", "w+") as myfile:				#overwrites wallet..
        			pickle.dump(chain.my, myfile)
		f_save_winfo()
		return

#def inspect_wallet():												# returns 3 lists of addresses, signatures and types..basic at present..
#	data = f_read_wallet()
#	if data is not False:
#			num_sigs = []
#			types = []
#			addresses = []
#			for x in range(len(data)):
#				addresses.append(data[x][0])
#				num_sigs.append(len(data[x][1]))
#				types.append(data[x][1][0].type)
#			return addresses, num_sigs, types
#	return False
	
def list_addresses():
	if not chain.my:
		addr = f_read_wallet()
	else:
		addr = chain.my

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
		
		if type(address[1]) == list:	
			list_addr.append([address[0], 'type:', address[1][0].type, 'balance: '+str(chain.state_balance(address[0])/100000000.000000000)+'('+str(chain.state_balance(address[0])/100000000.000000000+x/100000000.000000000)+')', 'nonce:'+str(chain.state_nonce(address[0]))+'('+str(chain.state_nonce(address[0])+y)+')', 'signatures left: '+str(address[1][0].signatures-chain.state_nonce(address[0]))+' ('+str(address[1][0].signatures-chain.state_nonce(address[0])-y)+'/'+str(address[1][0].signatures)+')' ])
		else:	#xmss
			list_addr.append([address[0], 'type:', address[1].type, 'balance: '+str(chain.state_balance(address[0])/100000000.000000000)+'('+str(chain.state_balance(address[0])/100000000.000000000+x/100000000.000000000)+')', 'nonce:'+str(chain.state_nonce(address[0]))+'('+str(chain.state_nonce(address[0])+y)+')', 'signatures left: '+str(address[1].remaining)+' ('+str(address[1].remaining)+'/'+str(address[1].signatures)+')'])

	return list_addr

def getnewaddress(signatures=4096, type='XMSS', SEED=None):						#new address format is a list of two items [address, data structure from random_mss call]
	addr = []
	if type == 'XMSS':
		new = merkle.XMSS(signatures=signatures, SEED=SEED)
		addr.append(new.address)
		addr.append(new)
	elif type == 'WOTS':
		new = merkle.random_wmss(signatures=signatures)
		addr.append(chain.roottoaddr(new[0].merkle_root))
		addr.append(new)
	elif type == 'LDOTS':
		new = merkle.random_ldmss(signatures=signatures)
		addr.append(chain.roottoaddr(new[0].merkle_root))
		addr.append(new)
	else: 
		raise Exception('OTS type not recognised')

	return addr

def xmss_getnewaddress(signatures=4096, SEED=None, type='WOTS+'):				#new address format returns a stateful XMSS class object
	return merkle.XMSS(signatures, SEED)


def savenewaddress(signatures=64, type='WOTS'):
	f_append_wallet(getnewaddress(signatures, type))
