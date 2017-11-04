# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import simplejson as json

# Initializers to be decided
from qrl.core import logger
from qrl.core.ESyncState import ESyncState

pending_blocks = {}
last_bk_time = None
last_ph_time = None
epoch_minimum_blocknumber = None


def set_epoch(blocknumber):
    # FIXME: epoch_minimum_blocknumber is local!
    epoch_minimum_blocknumber = blocknumber - blocknumber % 10000


def fork_recovery(blocknumber, chain, randomize_headerhash_fetch):
    set_epoch(blocknumber)
    global pending_blocks
    pending_blocks = {}
    randomize_headerhash_fetch(blocknumber - 1)
    chain.state.update(ESyncState.forked)                   # FIXME: this is confusing pstate with sync_state


def verify(suffix, peerIdentity, chain, randomize_headerhash_fetch):
    mini_block = json.loads(suffix)
    blocknumber = mini_block['blocknumber']

    if blocknumber in pending_blocks and pending_blocks[blocknumber][0] == peerIdentity:
        logger.info('Found in Fork Pending List')
        try:
            pending_blocks[blocknumber][3].cancel()
        except Exception as e:
            logger.exception(e)

        del pending_blocks[blocknumber]
        if mini_block['headerhash'] == chain.get_block(blocknumber).headerhash:  # Matched so fork root is the block next to it
            unfork(blocknumber + 1, chain)
            return

        if blocknumber >= epoch_minimum_blocknumber:
            randomize_headerhash_fetch(blocknumber - 1)
        else:
            logger.info('******Seems like chain has been forked in previous epoch... '
                        'Manual intervention is required!!!!!******')


def unfork(blocknumber, chain):
    sl = chain.stake_list_get()

    for blocknum in range(blocknumber, chain.height() + 1):
        stake_selector = chain.blockchain[blocknum].stake_selector
        for s in sl:
            if stake_selector == s[0]:
                s[2] -= 1

    del chain.blockchain[blocknumber:]
    chain.stake_list_put(sl)
    logger.info(('Forked chain has been removed from blocknumber ', blocknumber))
    chain.state.update(ESyncState.unsynced)             # FIXME: this is confusing pstate with sync_state
