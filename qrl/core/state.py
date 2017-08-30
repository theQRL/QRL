# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from operator import itemgetter

from qrl.core import db, logger, transaction, config
from qrl.crypto.misc import sha256


class State:
    """
        state functions
        first iteration - state data stored in leveldb file
        state holds address balances, the transaction nonce and a list of
        pubhash keys used for each tx - to prevent key reuse.
    """

    def __init__(self):
        self.db = db.DB()  # generate db object here

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.db is not None:
            del self.db
            self.db = None

    def stake_list_get(self):
        try:
            return self.db.get('stake_list')
        except KeyError:
            logger.warning('stake_list empty returning empty list')
        except Exception as e:
            logger.error('Exception in stake_list_get')
            logger.exception(e)

        return []

    def stake_list_put(self, sl):
        try:
            self.db.put('stake_list', sl)
        except Exception as e:
            logger.warning("stake_list_put: %s %s", type(e), e.message)
            return False

    def next_stake_list_get(self):
        try:
            return self.db.get('next_stake_list')
        except KeyError:
            logger.warning('next_stake_list empty returning empty list')
        except Exception as e:
            logger.error('Exception in next_stake_list_get')
            logger.exception(e)

        return []

    def next_stake_list_put(self, next_sl):
        try:
            self.db.put('next_stake_list', next_sl)
        except Exception as e:
            logger.warning("next_stake_list_put: %s %s", type(e), e.message)
            return False

    def put_epoch_seed(self, epoch_seed):
        try:
            self.db.put('epoch_seed', epoch_seed)
        except Exception as e:
            logger.exception(e)
            return False

    def get_epoch_seed(self):
        try:
            return self.db.get('epoch_seed')
        except Exception as e:
            logger.warning("get_epoch_seed: %s %s", type(e), e.message)
            return False

    def state_uptodate(self, height):  # check state db marker to current blockheight.
        if height == self.db.get('blockheight'):
            return True
        return False

    def state_blockheight(self):
        return self.db.get('blockheight')

    def state_get_txn_count(self, addr):
        try:
            return self.db.get('txn_count_' + addr)
        except KeyError:
            logger.warning('No txn count for %s', addr)
        except Exception as e:
            logger.error('Exception in state_get_txn_count')
            logger.exception(e)

        return 0

    def state_get_address(self, addr):
        try:
            return self.db.get(addr)
        except KeyError:
            logger.warning('state_get_address: No state found for %s', addr)
        except Exception as e:
            logger.error('Exception in state_get_address')
            logger.exception(e)

        return [0, 0, []]

    def state_address_used(self, addr):  # if excepts then address does not exist..
        try:
            return self.db.get(addr)
        except KeyError:
            logger.warning('state_address_used: address not found %s', addr)
        except Exception as e:
            logger.error('Exception in state_address_used')
            logger.exception(e)

        return False

    def state_balance(self, addr):
        try:
            return self.db.get(addr)[1]
        except KeyError:
            logger.warning("state_balance: state not found for %s", addr)
        except Exception as e:
            logger.error('Exception in state_balance')
            logger.exception(e)

        return 0

    def state_nonce(self, addr):
        try:
            return self.db.get(addr)[0]
        except KeyError:
            logger.warning("state_nonce: state not found for %s", addr)
        except Exception as e:
            logger.error('Exception in state_nonce')
            logger.exception(e)

        return 0

    def state_pubhash(self, addr):
        try:
            return self.db.get(addr)[2]
        except KeyError:
            logger.warning("state_pubhash: state not found for %s", addr)
        except Exception as e:
            logger.error('Exception in state_pubhash')
            logger.exception(e)

        return []

    def state_hrs(self, hrs):
        try:
            return self.db.get('hrs' + hrs)
        except KeyError:
            logger.warning("state_hrs: state not found for %s", hrs)
        except Exception as e:
            logger.error('Exception in state_hrs')
            logger.exception(e)

        return False

    def state_validate_tx_pool(self, chain):
        result = True

        for tx in chain.transaction_pool:
            block_chain_buffer = chain.block_chain_buffer
            tx_state = block_chain_buffer.get_stxn_state(blocknumber=block_chain_buffer.height()+1,
                                                         addr=tx.txfrom)
            if tx.state_validate_tx(tx_state=tx_state) is False:
                result = False
                logger.warning('tx %s failed', tx.txhash)
                chain.remove_tx_from_pool(tx)

        return result

    def state_add_block(self, chain, block):
        address_txn = dict()

        for tx in block.transactions:
            if tx.txfrom not in address_txn:
                address_txn[tx.txfrom] = self.state_get_address(tx.txfrom)
            if tx.subtype == transaction.TX_SUBTYPE_TX:
                if tx.txto not in address_txn:
                    address_txn[tx.txto] = self.state_get_address(tx.txto)

        # reminder contents: (state address -> nonce, balance, [pubhash]) (stake -> address, hash_term, nonce)

        next_sl = self.next_stake_list_get()
        sl = self.stake_list_get()

        blocks_left = block.blockheader.blocknumber - (block.blockheader.epoch * config.dev.blocks_per_epoch)
        blocks_left = config.dev.blocks_per_epoch - blocks_left

        if block.blockheader.blocknumber == 1:
            # Start Updating coin base txn
            tx = block.transactions[0]
            pub = tx.pub
            pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]

            pubhash = sha256(''.join(pub))

            if tx.nonce != address_txn[tx.txfrom][0] + 1:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.subtype)
                logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, address_txn[tx.txfrom][0] + 1)
                return False

            if pubhash in address_txn[tx.txfrom][2]:
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.subtype)
                return False


            address_txn[tx.txfrom][0] += 1
            address_txn[tx.txto][1] += tx.amount
            address_txn[tx.txfrom][2].append(pubhash)
            # Coinbase update end here

            for tx in block.transactions:
                if tx.subtype == transaction.TX_SUBTYPE_STAKE:
                    # update txfrom, hash and stake_nonce against genesis for current or next stake_list
                    if tx.txfrom == block.blockheader.stake_selector:
                        if tx.txfrom in chain.m_blockchain[0].stake_list:
                            sl.append([tx.txfrom, tx.hash, 1, tx.first_hash, tx.balance])
                            address_txn[tx.txfrom][0] += 1
                        else:
                            logger.warning('designated staker not in genesis..')
                            return False
                    else:
                        if tx.txfrom in chain.m_blockchain[0].stake_list:
                            sl.append([tx.txfrom, tx.hash, 0, tx.first_hash, tx.balance])
                        else:
                            next_sl.append([tx.txfrom, tx.hash, 0, tx.first_hash, tx.balance])

                    pubhash = tx.generate_pubhash(tx.pub)
                    address_txn[tx.txfrom][2].append(pubhash)

            epoch_seed = self.calc_seed(sl)
            chain.block_chain_buffer.epoch_seed = epoch_seed
            self.put_epoch_seed(epoch_seed)

            stake_list = sorted(sl, key=lambda staker: chain.score(stake_address=staker[0],
                                                                   reveal_one=sha256(str(staker[1])),
                                                                   balance=self.state_balance(staker[0]),
                                                                   seed=epoch_seed))

            if stake_list[0][0] != block.blockheader.stake_selector:
                logger.info('stake selector wrong..')
                return

            chain.my[0][1].hashchain(epoch=0)
            chain.hash_chain = chain.my[0][1].hc
            chain.wallet.f_save_wallet()

        else:

            logger.info('BLOCK: %s stake nonce: %s epoch: %s blocks_left: %s stake_selector %s',
                        block.blockheader.blocknumber,
                        block.blockheader.stake_nonce,
                        block.blockheader.epoch,
                        blocks_left - 1,
                        block.blockheader.stake_selector)

            found = False
            for s in sl:
                if block.blockheader.stake_selector == s[0]:
                    found = True
                    break

            if not found:
                logger.warning('stake selector not in stake_list_get')
                return

            # cycle through every tx in the new block to check state
            for tx in block.transactions:

                pub = tx.pub
                pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]

                pubhash = sha256(''.join(pub))

                if tx.nonce != address_txn[tx.txfrom][0] + 1:
                    logger.warning('nonce incorrect, invalid tx')
                    logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, address_txn[tx.txfrom][0] + 1)
                    return False

                if pubhash in address_txn[tx.txfrom][2]:
                    logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                    return False

                if tx.subtype == transaction.TX_SUBTYPE_TX:
                    if address_txn[tx.txfrom][1] - tx.amount < 0:
                        logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                        logger.warning('Buffer State Balance: %s  Transfer Amount %s', address_txn[tx.txfrom][1], tx.amount)
                        return False
                elif tx.subtype == transaction.TX_SUBTYPE_STAKE:
                    found = False
                    for s in next_sl:
                        # already in the next stake list, ignore for staker list but update as usual the state_for_address..
                        if tx.txfrom == s[0]:
                            found = True
                            if s[3] is None and tx.first_hash is not None:
                                threshold_block = self.get_staker_threshold_blocknum(next_sl, s[0])
                                epoch_blocknum = config.dev.blocks_per_epoch - blocks_left
                                if epoch_blocknum >= threshold_block - 1:
                                    s[3] = tx.first_hash
                                else:
                                    logger.warning('^^^^^^Rejected as %s %s', epoch_blocknum, threshold_block - 1)
                            break

                    address_txn[tx.txfrom][2].append(pubhash)

                    if not found:
                        next_sl.append([tx.txfrom, tx.hash, 0, tx.first_hash, tx.balance])

                address_txn[tx.txfrom][0] += 1

                if tx.subtype == transaction.TX_SUBTYPE_TX:
                    address_txn[tx.txfrom][1] -= tx.amount

                if tx.subtype in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                    address_txn[tx.txto][1] += tx.amount

                address_txn[tx.txfrom][2].append(pubhash)

        for address in address_txn:
            self.db.put(address, address_txn[address])

        if block.blockheader.blocknumber > 1 or block.blockheader.blocknumber == 1:
            self.stake_list_put(sl)
            self.next_stake_list_put(sorted(next_sl, key=itemgetter(1)))

        if blocks_left == 1:
            logger.info('EPOCH change: resetting stake_list, activating next_stake_list, updating PRF with '
                        'seed+entropy updating wallet hashchains..')

            sl = next_sl
            sl = filter(lambda staker: staker[3] is not None, sl)

            self.stake_list_put(sl)
            del next_sl[:]
            self.next_stake_list_put(next_sl)

            chain.my[0][1].hashchain(epoch=block.blockheader.epoch + 1)
            chain.hash_chain = chain.my[0][1].hc
            chain.wallet.f_save_wallet()

        self.db.put('blockheight', chain.height() + 1)
        logger.info('%s %s tx passed verification.', block.blockheader.headerhash, len(block.transactions))
        return True

    def calc_seed(self, sl, verbose=False):
        if verbose:
            logger.info('stake_list --> ')
            for s in sl:
                logger.info((s[0], s[3]))

        epoch_seed = 0

        for staker in sl:
            epoch_seed |= int(str(staker[3]), 16)

        return epoch_seed

    def get_staker_threshold_blocknum(self, next_stake_list, staker_address):
        tmp_next_stake_list = sorted(next_stake_list, key=itemgetter(4))
        total_stakers = len(next_stake_list)
        found_position = -1

        for i in range(total_stakers):
            if tmp_next_stake_list[i] == staker_address:
                found_position = i
                break

        if found_position < total_stakers // 2:
            return config.dev.low_staker_first_hash_block

        return config.dev.high_staker_first_hash_block

    def state_read_genesis(self, genesis_block):
        logger.info('genesis:')

        for address in genesis_block.state:
            self.db.put(address[0], address[1])
        return True

    def state_read_chain(self, chain):

        self.db.zero_all_addresses()
        c = chain.m_get_block(0).state
        for address in c:
            self.db.put(address[0], address[1])

        c = chain.m_read_chain()[2:]
        for block in c:

            # update coinbase address state
            stake_selector = self.state_get_address(block.blockheader.stake_selector)
            stake_selector[1] += block.blockheader.block_reward
            self.db.put(block.blockheader.stake_selector, stake_selector)

            for tx in block.transactions:
                pub = tx.pub
                if tx.type == 'TX':
                    pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]

                pubhash = sha256(''.join(pub))

                s1 = self.state_get_address(tx.txfrom)

                if s1[1] - tx.amount < 0:
                    logger.info((tx, tx.txfrom, 'exceeds balance, invalid tx', tx.txhash))
                    logger.info((block.blockheader.headerhash, 'failed state checks'))
                    return False

                if tx.nonce != s1[0] + 1:
                    logger.info(('nonce incorrect, invalid tx', tx.txhash))
                    logger.info((block.blockheader.headerhash, 'failed state checks'))
                    return False

                if pubhash in s1[2]:
                    logger.info(('public key re-use detected, invalid tx', tx.txhash))
                    logger.info((block.blockheader.headerhash, 'failed state checks'))
                    return False

                s1[0] += 1
                s1[1] = s1[1] - tx.amount
                s1[2].append(pubhash)
                self.db.put(tx.txfrom, s1)  # must be ordered in case tx.txfrom = tx.txto

                s2 = self.state_get_address(tx.txto)
                s2[1] = s2[1] + tx.amount

                self.db.put(tx.txto, s2)

            logger.info((block, str(len(block.transactions)), 'tx ', ' passed'))

        self.db.put('blockheight', chain.m_blockheight())
        return True
