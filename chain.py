#if we read the chainstate and it has no errors reading the chain, then we can rely upon that. For acute tx valid look to current state

__author__ = 'pete'

from bitcoin import sha256
from random import randint
import os
import sys
import merkle
import wallet
import pickle
import db

global transaction_pool
global m_blockchain
global my

m_blockchain = []
transaction_pool = []
block_state = []

print 'loading db'
db = db.DB()

class CreateSimpleTransaction(): 			#creates a transaction python class object which can be pickled and sent into the p2p network..

	def __init__(self, txfrom, txto, amount, data, fee=0, ots_key=0):
		if ots_key > len(data)-1:
			raise Exception('OTS key greater than available signatures')
		self.txfrom = txfrom
		self.nonce = state_nonce(txfrom)+1

		#search for any tx from txfrom already in the the transaction_pool, if so, they must be valid and the nonce must be adjusted..

		for t in transaction_pool:
			if t.txfrom == self.txfrom:
				self.nonce+=1

		self.txto = txto
		self.amount = amount
		self.fee = fee
		self.ots_key = ots_key
		self.pub = data[ots_key].pub
		self.type = data[ots_key].type
		self.txhash = sha256(''.join(self.txfrom+str(self.nonce)+self.txto+str(self.amount)+str(self.fee)))			#high level kludge!
		self.signature = merkle.sign_mss(data, self.txhash, self.ots_key)
		self.verify = merkle.verify_mss(self.signature, data, self.txhash, self.ots_key)
		#self.merkle_root = data[0].merkle_root #temporarily use ''.join although this is fixed..old addresses in wallet..
		self.merkle_root = ''.join(data[0].merkle_root)
		self.merkle_path = data[ots_key].merkle_path



# block functions and classes

def creategenesisblock():
	return CreateGenesisBlock()

def validate_block(block, last_block='default', verbose=0, new=0):		#check validity of new block..

	b = block.blockheader
	if sha256(str(b.blocknumber)+b.prev_blockheaderhash+str(b.number_transactions)+b.hashedtransactions) != block.blockheader.headerhash:
		return False

	if last_block=='default':
		if m_get_last_block().blockheader.headerhash != block.blockheader.prev_blockheaderhash:
			print 'yoyoyo'
			return False
		if m_get_last_block().blockheader.blocknumber != block.blockheader.blocknumber-1:
			print 'yldfkjlskfj'
			return False
	else:
		if m_get_block(last_block).blockheader.headerhash != block.blockheader.prev_blockheaderhash:
			return False
		if m_get_block(last_block).blockheader.blocknumber != block.blockheader.blocknumber-1:
			return False

	if validate_tx_in_block(block, new=new) == False:
		'print yaya'
		return False

	txhashes = []
	for transaction in block.transactions:
		txhashes.append(transaction.txhash)

	if sha256(''.join(txhashes)) != block.blockheader.hashedtransactions:
		return False

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


		# state code..
		# for each transaction there is a change in the state which much be recorded in the state part of the block. 


class State():
	# for each transaction we must check the old state, check the new state, calculate balance and attach the appropriate address and txhash. 

	def __init__(self, transaction_list):
		pass


class CreateGenesisBlock():			#first block has no previous header to reference..

	def __init__(self):
		self.blockheader = BlockHeader(blocknumber=0, prev_blockheaderhash=sha256('quantum resistant ledger'),number_transactions=0,hashedtransactions=sha256('0'))
		self.transactions = []
		self.state = [['Qa03e1af90a5f4ece073d686bf68168f6aee960be15dd557191089b3b29b591bdd748', [0, 10000, []]] , ['Q8213bd6365de0e81512e9caf26808638f1d1b58a01112c2591e02cb735b3f1356050',[0, 10000,[]]]]


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
	if validate_block(block_obj, new=1) is True:
		m_blockchain.append(block_obj)
		if state_add_block(m_get_last_block()) is True:
				remove_tx_in_block_from_pool(block_obj)
		else: 	
				m_remove_last_block()
				print 'last block failed state checks, removed from chain'
				return False
	else:
		print 'this point'
		return block_obj
	m_f_sync_chain()
	return True

def m_remove_last_block():
	if not m_blockchain:
		m_read_chain()
	m_blockchain.pop()

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

#state functions
#first iteration - state data stored in leveldb file
#state holds address balances, the transaction nonce and a list of pubhash keys used for each tx - to prevent key reuse.

def state_uptodate():									#check state db marker to current blockheight.
	if m_blockheight() == db.get('blockheight'):
		return True
	return False

def state_blockheight():
	return db.get('blockheight')

def state_get_address(addr):
	try: return db.get(addr)
	except:	return [0,0,[]]

def state_balance(addr):
	try: return db.get(addr)[1]
	#except:	return False
	except:	return 0 

def state_nonce(addr):
	try: return db.get(addr)[0]
	except: return 0
	#except:	return False

def state_pubhash(addr):
	try: return db.get(addr)[2]
	except: return []
	#except:	return False

# add some form of header hash check to confirm block correct..

def state_add_block(block):

	#ensure state at end of chain in memory

	print block, 'with: ', str(len(block.transactions)), ' tx'
	assert state_blockheight() == m_blockheight()-1, 'state leveldb not @ m_blockheight-1'

	#snapshot of state in case we need to revert to it..

	st1 = []
	st2 = []

	for tx in block.transactions:
		st1.append(state_get_address(tx.txfrom))
		st2.append(state_get_address(tx.txto))

	y = 0
	x = len(block.transactions)

	for tx in block.transactions:

		pub = tx.pub
		if tx.type == 'LDOTS':
				   pub = [i for sub in pub for i in sub]
		elif tx.type == 'WOTS':
				pass
		pubhash = sha256(''.join(pub))

		s1 = state_get_address(tx.txfrom)
		
		if s1[1] - tx.amount < 0:
			print tx, tx.txfrom, 'exceeds balance, invalid tx'
			#return False
			break

		if tx.nonce != s1[0]+1:
			print 'nonce incorrect, invalid tx'
			print tx, tx.txfrom, tx.nonce
			#return False
			break

		s1[0]+=1
		s1[1] = s1[1]-tx.amount
		s1[2].append(pubhash)
		db.put(tx.txfrom, s1)

		s2 = state_get_address(tx.txto)
		s2[1] = s2[1]+tx.amount
		s2[2].append(pubhash)
		db.put(tx.txto, s2)

		y+=1

#	print str(y), str(len(block.transactions))

	# if we havent done all the tx in the block we have break, need to revert state back to before the change.

	if y<len(block.transactions):
		print 'failed to state check entire block'
		print 'reverting state'

		for x in range(len(block.transactions)):
			db.put(block.transactions[x].txfrom, st1[x])
			db.put(block.transactions[x].txto, st2[x])

		return False

	db.put('blockheight', m_blockheight())
	print block, str(len(block.transactions)),'tx ',' passed'
	return True


def state_read_chain():

	db.zero_all_addresses()
	c = m_get_block(0).state
	for address in c:
		db.put(address[0], address[1])

	c = m_read_chain()[1:]

	for block in c:

		for tx in block.transactions:
			pub = tx.pub
			if tx.type == 'LDOTS':
				  	pub = [i for sub in pub for i in sub]
			elif tx.type == 'WOTS':
					pass
			pubhash = sha256(''.join(pub))

			s1 = state_get_address(tx.txfrom)

			if s1[1] - tx.amount < 0:
				print tx, tx.txfrom, 'exceeds balance, invalid tx'
				return False

			if tx.nonce != s1[0]+1:
				print 'nonce incorrect, invalid tx'
				return False

			s1[0]+=1
			s1[1] = s1[1]-tx.amount
			s1[2].append(pubhash)
			db.put(tx.txfrom, s1)							#must be ordered in case tx.txfrom = tx.txto

			s2 = state_get_address(tx.txto)
			s2[1] = s2[1]+tx.amount
			s2[2].append(pubhash)
			db.put(tx.txto, s2)			

		print block, str(len(block.transactions)), 'tx ', ' passed'
	db.put('blockheight', m_blockheight())
	return True

#tx functions and classes

def createsimpletransaction(txfrom, txto, amount, data, fee=0, ots_key=0):

	#few state checks to ensure tx is valid..

	if state_uptodate() is False:
			print 'state not at latest block in chain'
			return False

	if state_balance(txfrom) is 0:
			print 'empty address'
			return False 

	if state_balance(txfrom) < amount: 
			print 'insufficient funds for valid tx'
			return False

	return CreateSimpleTransaction(txfrom, txto, amount, data, fee, ots_key)

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

def validate_tx_in_block(block_obj, new=0):
	x = 0
	for transaction in block_obj.transactions:
		if validate_tx(transaction, new=new) is False:
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

def validate_tx(tx, new=0):

	#cryptographic checks

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


# debugging functions

def test_tx(n):
	for x in range(n):
		create_my_tx(randint(0,5), randint(0,5),0.06)

def create_my_tx(txfrom, txto, n):
	my = wallet.f_read_wallet()
	tx = createsimpletransaction(txto=my[txto][0],txfrom=my[txfrom][0],amount=n, data=my[txfrom][1])
	if tx is not False:
		transaction_pool.append(tx)
	return tx

def create_some_tx(n):				#create tx for debugging
	for x in range(n):
		a,b = wallet.getnewaddress(), wallet.getnewaddress()
		transaction_pool.append(createsimpletransaction(a[0],b[0],10,a[1]))



