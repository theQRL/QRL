# leveldb code for maintaining account state data
__author__ = 'pete'

import leveldb
import pickle

class DB():

	def __init__(self, dbfile='./state'):
		leveldb.DestroyDB(dbfile)
		self.db = leveldb.LevelDB(dbfile)

	def return_all_addresses(self):
		addresses = []
		for k,v in self.db.RangeIter('Q'):					#need a way to zero all the balances prior to rerunnning state_read_chain..
			if k[0] == 'Q': addresses.append(k)
		return addresses

	def total_coin_supply(self):
		coins = 0
		for k,v in self.db.RangeIter('Q'):
			if k[0] == 'Q':
				#print pickle.loads(v)[1]
				coins = coins + pickle.loads(v)[1]
		return coins

	def zero_all_addresses(self):
		addresses = []
		for k,v in self.db.RangeIter('Q'):
			addresses.append(k)
		for address in addresses:
			self.put(address, [0,0,[]])
		self.put('blockheight', 0)
		return

	def destroy(self, dbfile='./state'):
		leveldb.DestroyDB('./state')

	def put(self, key_obj, value_obj):					#serialise with pickle into a string 
		#if isinstance(value_obj, list):
		value_obj = pickle.dumps(value_obj)
		self.db.Put(key_obj, value_obj)
		return

	def get(self, key_obj):
		value_obj = self.db.Get(key_obj)
		try:
		 	return pickle.loads(value_obj)
		except:
			return value_obj



	def delete(self, key_obj):
		self.db.Delete(key_obj)
		return
