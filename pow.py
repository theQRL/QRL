# proof of work functions..


from bitcoin import sha256
from bitcoin import random_key
from time import time
from random import randint

import chain

__author__ = 'pete'


def pow_find_block():
	h_hash = chain.m_get_last_block().blockheader.headerhash
	diff = 2**chain.m_get_last_block().blockheader.difficulty
	y = randint(0,2**255)
	for x in range(y,y+1000000):
		if int(sha256(h_hash+str(x)),16) < diff:
				print str(x), 'attempts, MINED block at diff 2**', str(chain.m_get_last_block().blockheader.difficulty)
				return str(x)
	return False



def calculate_difficulty():
	return

def pow_n(n):
	
	starting_time = time()
	diff = 2**n
	y = 0

	times = 0
	for p in range(100):
		hash_h = sha256(random_key())
		for x in range(10000000):
			if int(sha256(hash_h+str(x)),16) < diff:
				print str(y), str(x), 'attempts to beat difficulty 2**', str(n), 'elapsed..', str(time()-starting_time)
				times +=time()-starting_time
				break
		y+=1
		starting_time = time()

	print 'mean ', str(times/100), 'seconds'



def pow_countdown():
	hash_h = sha256('pete')
	starting_time = time()
	for p in range(256,-1,-1):
	 	diff = 2**p
	 	for x in range(100000000):
			if int(sha256(hash_h+str(x)), 16) < diff:
				print str(x), 'attempts to beat difficulty 2**', str(p), 'elapsed..', str(time()-starting_time)
				break

		starting_time = time()



	# sha256(headerhash + nonce)