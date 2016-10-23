# leveldb code for maintaining account state data
__author__ = 'pete'

import leveldb
import pickle

class DB():

	def __init__(self, dbfile='./state'):	
		self.db = leveldb.LevelDB(dbfile)

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
