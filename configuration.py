################################################################
#                   Configuration for users                    #
################################################################
#Staking Configuration
enable_auto_staking = True

#PEER Configuration
enable_peer_discovery = True  # Allows to discover new peers from the connected peers
peer_list = ['104.237.3.184']  # Atleast one active peer IP required
max_peers_limit = 10 # Number of allowed peers
################################################################
#                       END                                    #
################################################################





################################################################
# Warning: Don't change following configuration.               #
#          For QRL Developers only                             #
################################################################
public_ip="13.59.217.44"
minimum_required_stakers = 5
minimum_staking_balance_required = 1
blocks_per_epoch = 100
reorg_limit = 3
hashchain_nums = 50	# 1 Primary and rest Secondary hashchain
block_creation_seconds = 55
message_q_size = 1000
message_receipt_timeout = 10 # request timeout for full message
stake_before_x_blocks = 50
low_staker_first_hash_block = 70
high_staker_first_hash_block = 80
N = 256 # Constant used in Block winner formula
POS_delay_after_block = 15
message_buffer_size = 1024*1024 #  1 MB
################################################################
#                       END                                    #
################################################################
