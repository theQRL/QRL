__author__ = 'pete'

from bitcoin import sha256
import os
import merkle
import wallet
import pickle

# each account is created from the merkle root of a MSS 
# account address = 'Q' + sha256(root)+ sha256(sha256(root))[:4]
# Thus each address starts with Q and has a 4 byte double hashed appended checksum.
# transactions originate from accounts and transfer units to one or many other addresses.

# transactions are class objects transmitted as pickled bytestreams.
# blocks are class objects as below, and are transmitted as pickled bytestreams.
# each block has a header, then body.
# the header is as follows: class object containing - 
# the body is simply a list of transaction class objects


global transaction_pool
transaction_pool = []

def roottoaddr(merkle_root):
	return 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4]

def checkaddress(merkle_root, address):
	if 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4] == address:
		return True
	else: 
		return False

def createsimpletransaction(txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
	return CreateSimpleTransaction(txfrom, txto, amount, data, fee, nonce, ots_key)

def creategenesisblock():
	return CreateGenesisBlock()

def bytestream(obj):
	return pickle.dumps(obj)

def tx_bytestream(tx_obj):
	return 'TT'+bytestream(tx_obj)

def bk_bytestream(block_obj):
	return 'BK'+bytestream(block_obj)

def f_read_chain():

	block_list = []

	if os.path.isfile('./chain.dat') is False:
		print 'Creating new chain file'
		block_list.append(creategenesisblock())
		with open("./chain.dat", "a") as myfile:				#add in a new call to create random_otsmss
        		pickle.dump(block_list, myfile)

	try:
			print 'loading blockchain to memory..'
			with open('./chain.dat', 'r') as myfile:
				return pickle.load(myfile)
	except:
			print 'IO error'
			return False
	


def f_append_block(block_data):

		data2 = f_read_chain()
		data2.append(block_data)
		if block_data is not False:
			print 'Appending block to chain'
			with open("./chain.dat", "w+") as myfile:				#overwrites wallet..
        			pickle.dump(data2, myfile)
		return

def add_tx_to_pool(tx_class_obj):
	transaction_pool.append(tx_class_obj)

class CreateSimpleTransaction(): 			#creates a transaction python class object which can be pickled and sent into the p2p network..

	def __init__(self, txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
		if ots_key > len(data)-1:
			raise Exception('OTS key greater than available signatures')

		self.txfrom = txfrom
		self.nonce = nonce
		self.txto = txto
		self.amount = amount
		self.fee = fee
		self.ots_key = ots_key
		self.pub = data[ots_key].pub
		self.type = data[ots_key].type

		self.txhash = sha256(''.join(self.txfrom+str(self.nonce)+self.txto+str(self.amount)+str(self.fee)))			#high level kludge!
		self.signature = merkle.sign_mss(data, self.txhash, self.ots_key)
		self.verify = merkle.verify_mss(self.signature, data, self.txhash, self.ots_key)
		
		self.merkle_root = data[0].merkle_root
		self.merkle_path = data[ots_key].merkle_path


class BlockHeader():

	def __init__(self, blocknumber, prev_blockheaderhash, number_transactions, hashedtransactions ):
		self.blocknumber = blocknumber
		self.prev_blockheaderhash = prev_blockheaderhash
		self.number_transactions = number_transactions
		self.hashedtransactions = hashedtransactions
		self.headerhash = sha256(str(self.blocknumber)+self.prev_blockheaderhash+str(self.number_transactions)+self.hashedtransactions)



class CreateBlock():

	def __init__(self, blocknumber, prev_blockheaderhash, transaction_pool):
		pass



class CreateGenesisBlock():			#first block has no previous header to reference..

	def __init__(self):
		self.blockheader = BlockHeader(blocknumber=0, prev_blockheaderhash=sha256('quantum resistant ledger'),number_transactions=0,hashedtransactions=sha256('0'))

	