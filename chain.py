__author__ = 'pete'

from bitcoin import sha256
import os
import merkle
import wallet
import pickle

global transaction_pool
global m_blockchain

m_blockchain = []
transaction_pool = []

# address functions

def roottoaddr(merkle_root):
	return 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4]

def checkaddress(merkle_root, address):
	if 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4] == address:
		return True
	else:
		return False

# network functions

def bytestream(obj):
	return pickle.dumps(obj)

def tx_bytestream(tx_obj):
	return 'TT'+bytestream(tx_obj)

def bk_bytestream(block_obj):
	return 'BK'+bytestream(block_obj)

# chain functions

def f_read_chain():
	block_list = []
	if os.path.isfile('./chain.dat') is False:
		print 'Creating new chain file'
		block_list.append(creategenesisblock())
		with open("./chain.dat", "a") as myfile:				#add in a new call to create random_otsmss
        		pickle.dump(block_list, myfile)
	try:
			with open('./chain.dat', 'r') as myfile:
				return pickle.load(myfile)
	except:
			print 'IO error'
			return False

def inspect_chain():												# returns 3 lists of addresses, signatures and types..basic at present..
	data = f_read_chain()
	if data is not False:
			#num_sigs = []
			#types = []
			blocks = []
			#for x in range(len(data)):
				#addresses.append(data[x][0])
				#num_sigs.append(len(data[x][1]))
				#types.append(data[x][1][0].type)
			#return addresses, num_sigs, types
			return len(data)
	return False

def f_add_block():
	
	f_append_block(CreateBlock())
	flush_tx_pool()
	return

def f_get_last_block():
	data = f_read_chain()
	return data[len(data)-1]

def f_append_block(block_data):
		data2 = f_read_chain()
		data2.append(block_data)
		if block_data is not False:
			print 'Appending block to chain'
			with open("./chain.dat", "w+") as myfile:				#overwrites wallet..
        			pickle.dump(data2, myfile)
		return

#tx functions and classes

def createsimpletransaction(txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
	return CreateSimpleTransaction(txfrom, txto, amount, data, fee, nonce, ots_key)

def add_tx_to_pool(tx_class_obj):
	transaction_pool.append(tx_class_obj)

def remove_tx_from_pool(tx_class_obj):
	transaction_pool.remove(tx_class_obj)

def remove_tx_from_block(tx_obj, block_obj):
	block_obj.remove(tx_obj)

def show_tx_pool():
	return transaction_pool

def flush_tx_pool():
	del transaction_pool[:]

def validate_tx_in_block(block_obj):
	x = 0
	for transaction in block_obj.transactions:
		if validate_tx(transaction) is False:
			print 'invalid tx: ',transaction, 'in block'
			x+=1
	if x > 0:
		return False
	return True

def validate_tx_pool(transaction_pool):									#invalid transactions are auto removed from pool..
	for transaction in transaction_pool:
		if validate_tx(transaction) is False:
			remove_tx_from_pool(transaction)
			print 'invalid tx: ',transaction, 'removed from pool'

def validate_tx(tx):
	#todo - from blockchain - check nonce + public key, check balance is valid.
	if not tx:
		raise Exception('No transaction to validate.')

	if tx.type == 'WOTS':
		if merkle.verify_wkey(tx.signature, tx.txhash, tx.pub) is False:
				return False
	elif tx.type == 'LDOTS':
		if merkle.verify_lkey(tx.signature, tx.txhash, tx.pub) is False:
				return False
	else: 
		return False

	if checkaddress(tx.merkle_root, tx.txfrom) is False:
			return False

	if merkle.verify_root(tx.pub, tx.merkle_root, tx.merkle_path) is False:
			return False
	return True

def create_some_tx(n):				#create tx for debugging
	for x in range(n):
		a,b = wallet.getnewaddress(), wallet.getnewaddress()
		transaction_pool.append(createsimpletransaction(a[0],b[0],10,a[1]))

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

# block functions and classes

def creategenesisblock():
	return CreateGenesisBlock()

def validate_block(block):		#check validity of new block..
	b = block.blockheader
	if sha256(str(b.blocknumber)+b.prev_blockheaderhash+str(b.number_transactions)+b.hashedtransactions) != block.blockheader.headerhash:
		return False

	if f_get_last_block().blockheader.headerhash != block.blockheader.prev_blockheaderhash:
		return False

	if f_get_last_block().blockheader.blocknumber != block.blockheader.blocknumber-1:
		return False
	
	if validate_tx_in_block(block) == False:
		return False

	txhashes = []
	for transaction in block.transactions:
		txhashes.append(transaction.txhash)
	
	if sha256(''.join(txhashes)) != block.blockheader.hashedtransactions:
		return False

	# add code to validate individual tx based upon actual blockchain..

	return True

class BlockHeader():

	def __init__(self, blocknumber, prev_blockheaderhash, number_transactions, hashedtransactions ):
		self.blocknumber = blocknumber
		self.prev_blockheaderhash = prev_blockheaderhash
		self.number_transactions = number_transactions
		self.hashedtransactions = hashedtransactions
		self.headerhash = sha256(str(self.blocknumber)+self.prev_blockheaderhash+str(self.number_transactions)+self.hashedtransactions)

class CreateBlock():

	def __init__(self):
		data = f_get_last_block()
		lastblocknumber = data.blockheader.blocknumber
		prev_blockheaderhash = data.blockheader.headerhash
		if not transaction_pool:
			hashedtransactions = sha256('')
		else:
			txhashes = []
			for transaction in transaction_pool:
				txhashes.append(transaction.txhash)
			hashedtransactions = sha256(''.join(txhashes))
		self.transactions = transaction_pool						#add transactions in pool to block
		self.blockheader = BlockHeader(blocknumber=lastblocknumber+1, prev_blockheaderhash=prev_blockheaderhash, number_transactions=len(transaction_pool), hashedtransactions=hashedtransactions)


class CreateGenesisBlock():			#first block has no previous header to reference..

	def __init__(self):
		self.blockheader = BlockHeader(blocknumber=0, prev_blockheaderhash=sha256('quantum resistant ledger'),number_transactions=0,hashedtransactions=sha256('0'))
