__author__ = 'pete'

from bitcoin import sha256
import merkle
import wallet
import pickle

# each account is created from the merkle root of a MSS 
# account address = 'Q' + sha256(address)+ sha256(sha256(address))[:4]
# Thus each address starts with Q and has a 4 byte appended checksum.
# transactions originate from accounts and transfer units to one or many other addresses.

# each transaction FROM an account has a sequentially incremented nonce.
# each transaction contains:
# txfrom : account address
# nonce : number containing the transaction count for the address.
# no. of sender addresses,
# tuple of (txto to address , txamount)
# fee
# hash of above (txhash)
# signature of txhash using MSS key linked to merkle root and from which the address can be derived.
# public key
# merkle path to root (to be optimised later)
#
# Validating nodes upon seeing the transaction are able to check if the nonce matches the blockchain for the sending account
# (signatures should only be used once!, public keys are public and so can be checked..)
# The signature can be verified from the txhash (message) and the public key. 
# The account address can be verified as as being linked to the keypair by hashing the public key and checking the auth proofs
#
# As this is a high level language driven blockchain, transaction structures will be pickled into binary form and transmitted,
# and unconventially unpickled by nodes and inspected in data structure form for validity.
#

def roottoaddr(merkle_root):
	return 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4]

def checkaddress(merkle_root, address):
	if 'Q'+sha256(merkle_root)+sha256(sha256(merkle_root))[:4] == address:
		return True
	else: 
		return False


def createsimpletransaction(txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
	return CreateSimpleTransaction(txfrom, txto, amount, data, fee, nonce, ots_key)



class CreateSimpleTransaction(): 			#creates a transaction python class object which can be pickled and sent into the p2p network..

	def __init__(self, txfrom, txto, amount, data, fee=0, nonce=0, ots_key=0):
		self.txfrom = txfrom
		self.nonce = nonce
		self.txto = txto
		self.amount = amount
		self.fee = fee
		self.ots_key = ots_key

		self.txhash = sha256(''.join(self.txfrom+str(self.nonce)+self.txto+str(self.amount)+str(self.fee)))			#high level kludge!

		self.signature = merkle.sign_mss(data, self.txhash, self.ots_key)

		self.pub = data[ots_key].pub

		self.merkle_root = data[0].merkle_root

		self.merkle_path = data[ots_key].merkle_path







	