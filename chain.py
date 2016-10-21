__author__ = 'pete'

from bitcoin import sha256
import os
import sys
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

def f_get_last_block():
	return f_read_chain()[-1]

def f_write_chain(block_data):											
		data = f_read_chain()
		for block in block_data:
				data.append(block)
		if block_data is not False:
			print 'Appending data to chain'
			with open("./chain.dat", "w+") as myfile:				#overwrites wallet..must use w+ as cannot append pickle item
        			pickle.dump(data, myfile)
		return

def m_load_chain():
	del m_blockchain[:]
	for block in f_read_chain():
		m_blockchain.append(block)
	return m_blockchain

def m_read_chain():
	if not m_blockchain:
		m_load_chain()
	return m_blockchain

def m_get_block(n):
	return m_read_chain()[n]

def m_get_last_block():
	return m_read_chain()[-1]

def m_create_block():
	return CreateBlock()

def m_add_block(block_obj):
	if not m_blockchain:
		m_read_chain()
	if validate_block(block_obj) is True:
		m_blockchain.append(block_obj)
		remove_tx_in_block_from_pool(block_obj)
	else:
		return False
	return True

def m_blockheight():
	return len(m_read_chain())-1

def m_info_block(n):
	if n > m_blockheight():
		print 'No such block exists yet..'
		return False
	b = m_get_block(n)
	print 'Block: ', b, str(b.blockheader.blocknumber)
	print 'Blocksize, ', str(len(bytestream(b)))
	print 'Number of transactions: ', str(len(b.transactions))
	print 'Validates: ', validate_block(b, last_block = n-1)

def m_f_sync_chain():
	f_write_chain(m_read_chain()[f_get_last_block().blockheader.blocknumber+1:])
	
def m_verify_chain(verbose=0):
	n = 0
	for block in m_read_chain()[1:]:
		if validate_block(block,last_block=n, verbose=verbose) is False:
				return False
		n+=1
		if verbose is 1:
			sys.stdout.write('.')
			sys.stdout.flush()
	return True

#tx functions and classes

def createsimpletransaction(txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
	return CreateSimpleTransaction(txfrom, txto, amount, data, fee, nonce, ots_key)

def add_tx_to_pool(tx_class_obj):
	transaction_pool.append(tx_class_obj)

def remove_tx_from_pool(tx_class_obj):
	transaction_pool.remove(tx_class_obj)

def show_tx_pool():
	return transaction_pool

def remove_tx_in_block_from_pool(block_obj):
	for tx in block_obj.transactions:
		if tx in transaction_pool:
			remove_tx_from_pool(tx)

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

def validate_tx_pool():									#invalid transactions are auto removed from pool..
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

def validate_block(block, last_block='default', verbose=0):		#check validity of new block..

	b = block.blockheader
	if sha256(str(b.blocknumber)+b.prev_blockheaderhash+str(b.number_transactions)+b.hashedtransactions) != block.blockheader.headerhash:
		return False

	if last_block=='default':
		if m_get_last_block().blockheader.headerhash != block.blockheader.prev_blockheaderhash:
			return False
		if m_get_last_block().blockheader.blocknumber != block.blockheader.blocknumber-1:
			return False
	else:
		if m_get_block(last_block).blockheader.headerhash != block.blockheader.prev_blockheaderhash:
			return False
		if m_get_block(last_block).blockheader.blocknumber != block.blockheader.blocknumber-1:
			return False

	if validate_tx_in_block(block) == False:
		return False

	txhashes = []
	for transaction in block.transactions:
		txhashes.append(transaction.txhash)

	if sha256(''.join(txhashes)) != block.blockheader.hashedtransactions:
		return False

	# add code to validate individual tx based upon actual blockchain..

	if verbose==1:
		print block, 'True'

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
		data = m_get_last_block()
		lastblocknumber = data.blockheader.blocknumber
		prev_blockheaderhash = data.blockheader.headerhash
		if not transaction_pool:
			hashedtransactions = sha256('')
		else:
			txhashes = []
			for transaction in transaction_pool:
				txhashes.append(transaction.txhash)
			hashedtransactions = sha256(''.join(txhashes))
		self.transactions = []
		for tx in transaction_pool:
			self.transactions.append(tx)						#copy memory rather than sym link
		self.blockheader = BlockHeader(blocknumber=lastblocknumber+1, prev_blockheaderhash=prev_blockheaderhash, number_transactions=len(transaction_pool), hashedtransactions=hashedtransactions)


class CreateGenesisBlock():			#first block has no previous header to reference..

	def __init__(self):
		self.blockheader = BlockHeader(blocknumber=0, prev_blockheaderhash=sha256('quantum resistant ledger'),number_transactions=0,hashedtransactions=sha256('0'))
		self.transactions = []