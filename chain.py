__author__ = 'pete'

from bitcoin import sha256
import merkle
import wallet
import pickle

# each account is created from the merkle root of a MSS 
# account address = 'Q' + sha256(root)+ sha256(sha256(root))[:4]
# Thus each address starts with Q and has a 4 byte double hashed appended checksum.
# transactions originate from accounts and transfer units to one or many other addresses.


def roottoaddr(merkle_root):
	return 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4]

def checkaddress(merkle_root, address):
	if 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4] == address:
		return True
	else: 
		return False


def createsimpletransaction(txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
	return CreateSimpleTransaction(txfrom, txto, amount, data, fee, nonce, ots_key)

def bytestream(obj):
	return pickle.dumps(obj)


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


class CreateBlock():

	def __init__(self):	




	