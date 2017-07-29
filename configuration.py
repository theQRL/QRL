################################################################
#                   Configuration for users                    #
################################################################
#Staking Configuration
enable_auto_staking = False

#PEER Configuration
enable_peer_discovery = True  # Allows to discover new peers from the connected peers
peer_list = ['104.251.219.145']  # Atleast one active peer IP required
max_peers_limit = 10 # Number of allowed peers
################################################################
#                       END                                    #
################################################################





################################################################
# Warning: Don't change following configuration.               #
#          For QRL Developers only                             #
################################################################
minimum_required_stakers = 3
minimum_staking_balance_required = 1
blocks_per_epoch = 10000
reorg_limit = 3
hashchain_nums = 50	# 1 Primary and rest Secondary hashchain
block_creation_seconds = 55
message_q_size = 1000
message_receipt_timeout = 10 # request timeout for full message
stake_before_x_blocks = 5000
low_staker_first_hash_block = 7000
high_staker_first_hash_block = 8000
N = 256 # Constant used in Block winner formula
POS_delay_after_block = 15
################################################################
#                       END                                    #
################################################################
