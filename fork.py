import json

#Initializers to be decided
pending_blocks = {}
last_bk_time = None
last_ph_time = None
epoch_minimum_blocknumber = None

def set_epoch(blocknumber):
	epoch_minimum_blocknumber = blocknumber - blocknumber % 10000

def fork_recovery(blocknumber, chain, randomize_headerhash_fetch):
	global pending_blocks
	pending_blocks = {}
	randomize_headerhash_fetch(blocknumber-1)
	chain.state.update('forked')
	#change state to FORKED
	#call headerhash_lookup in reverse

def verify(suffix, peerIdentity, chain, randomize_headerhash_fetch):
	mini_block = json.loads(suffix)
	blocknumber = mini_block['blocknumber']
	if blocknumber in pending_blocks and pending_blocks[blocknumber][0] == peerIdentity:
		printL (( 'Found in Fork Pending List' ))
		try: pending_blocks[blocknumber][3].cancel()
		except Exception: pass
		del pending_blocks[blocknumber]
		if mini_block['headerhash'] == chain.m_get_block(blocknumber).blockheader.headerhash: #Matched so fork root is the block next to it
			unfork(blocknumber+1, chain)
			return
		if blocknumber >= epoch_minimum_blocknumber:
			randomize_headerhash_fetch(blocknumber-1)
		else:
			printL (( '******Seems like chain has been forked in previous epoch... Manual intervention is required!!!!!******' ))

def unfork(blocknumber, chain):
	sl = chain.stake_list_get()
	for blocknum in xrange(blocknumber, chain.m_blockheight()+1):
		stake_selector = chain.m_blockchain[blocknum].blockheader.stake_selector
		for s in sl:
			if stake_selector == s[0]:
				s[2]-=1
	del chain.m_blockchain[blocknumber:]
	chain.stake_list_put(sl)
	printL (( 'Forked chain has been removed from blocknumber ', blocknumber ))
	chain.state.update('unsynced')
#def headerhash_lookup(blocknumber):
#reactor.callLater(15, 
