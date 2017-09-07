# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from operator import itemgetter

from qrl.core import db, logger, transaction, config, helper
from qrl.core.StakeValidatorsList import StakeValidatorsList
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import hashchain
import sys

class State:
    """
        state functions
        first iteration - state data stored in leveldb file
        state holds address balances, the transaction nonce and a list of
        pubhash keys used for each tx - to prevent key reuse.
    """

    def __init__(self):
        self.db = db.DB()  # generate db object here
        self.stake_validators_list = StakeValidatorsList()

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
            self.db.put('stake_list', self.stake_validators_list.to_json())
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
        self.load_address_state(chain, block, address_txn)

        if block.blockheader.blocknumber == 1:
            if not self.state_update_genesis(chain, block, address_txn):
                return False
            self.commit(chain, block, address_txn)
            return True

        if not self.state_update(block, self.stake_validators_list, address_txn) and False:  # To be removed before next hard fork
            return

        self.commit(chain, block, address_txn)

        return True

    # Loads the state of the addresses mentioned into txn
    def load_address_state(self, chain, block, address_txn):
        blocknumber = block.blockheader.blocknumber

        for tx in block.transactions:
            if tx.txfrom not in address_txn:
                address_txn[tx.txfrom] = chain.block_chain_buffer.get_stxn_state(blocknumber, tx.txfrom)
            if tx.subtype == transaction.TX_SUBTYPE_TX:
                if tx.txto not in address_txn:
                    address_txn[tx.txto] = chain.block_chain_buffer.get_stxn_state(blocknumber, tx.txto)

        return address_txn

    def state_update_genesis(self, chain, block, address_txn):
        # Start Updating coin base txn
        tx = block.transactions[0]  # Expecting only 1 txn of COINBASE subtype in genesis block
        pubhash = tx.generate_pubhash(tx.pub)

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
                        self.stake_validators_list.add_sv(tx.txfrom, tx.hash, tx.first_hash, tx.balance)
                        address_txn[tx.txfrom][0] += 1
                    else:
                        logger.warning('designated staker not in genesis..')
                        return False
                else:
                    if tx.txfrom in chain.m_blockchain[0].stake_list:
                        self.stake_validators_list.add_sv(tx.txfrom, tx.hash, tx.first_hash, tx.balance)
                    else:
                        self.stake_validators_list.add_sv(tx.txfrom, tx.hash, tx.first_hash, tx.balance)

                pubhash = tx.generate_pubhash(tx.pub)
                address_txn[tx.txfrom][2].append(pubhash)

        epoch_seed = self.stake_validators_list.calc_seed()
        chain.block_chain_buffer.epoch_seed = epoch_seed
        self.put_epoch_seed(epoch_seed)

        top_st = None
        score = sys.maxint
        for staker in self.stake_validators_list.sv_list:
            sv = self.stake_validators_list.sv_list[staker]
            new_score = chain.score(stake_address=staker,
                                    reveal_one=sha256(str(sv.cache_hash)),
                                    balance=sv.balance,
                                    seed=epoch_seed)
            if new_score < score:
                score = new_score
                top_st = staker

        if top_st != block.blockheader.stake_selector:
            logger.info('stake selector wrong..')
            return

        chain.my[0][1].hashchain(epoch=0)
        chain.hash_chain = chain.my[0][1].hc
        chain.wallet.f_save_wallet()
        return True

    def state_update(self, block, stake_validators_list, address_txn):

        # reminder contents: (state address -> nonce, balance, [pubhash]) (stake -> address, hash_term, nonce)

        blocks_left = helper.get_blocks_left(block.blockheader.blocknumber)

        logger.info('BLOCK: %s epoch: %s blocks_left: %s stake_selector %s',
                    block.blockheader.blocknumber,
                    block.blockheader.epoch,
                    blocks_left - 1,
                    block.blockheader.stake_selector)

        if block.blockheader.stake_selector not in stake_validators_list.sv_list:
            logger.warning('stake selector not in stake_list_get')
            return

        # cycle through every tx in the new block to check state
        for tx in block.transactions:

            pubhash = tx.generate_pubhash(tx.pub)

            if tx.nonce != address_txn[tx.txfrom][0] + 1:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.subtype)
                logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, address_txn[tx.txfrom][0] + 1)
                return False

            if pubhash in address_txn[tx.txfrom][2]:
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.subtype)
                return False

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                if address_txn[tx.txfrom][1] - tx.amount < 0:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s', address_txn[tx.txfrom][1], tx.amount)
                    return False

            elif tx.subtype == transaction.TX_SUBTYPE_STAKE:
                epoch_blocknum = config.dev.blocks_per_epoch - blocks_left
                if (not tx.first_hash) and epoch_blocknum >= config.dev.stake_before_x_blocks:
                    logger.warning('Block rejected #%s due to ST without first_reveal beyond limit',
                                   block.blockheader.blocknumber)
                    logger.warning('Stake_selector: %s', block.blockheader.stake_selector)
                    logger.warning('epoch_blocknum: %s Threshold: %s',
                                   epoch_blocknum,
                                   config.dev.stake_before_x_blocks)
                    return False

                address_txn[tx.txfrom][2].append(pubhash)
                next_sv_list = stake_validators_list.next_sv_list
                if tx.txfrom in next_sv_list:
                    if next_sv_list[tx.txfrom].first_hash is None and tx.first_hash is not None:
                        threshold_blocknum = stake_validators_list.get_threshold(tx.txfrom)
                        if epoch_blocknum < threshold_blocknum - 1:
                            logger.warning('Block rejected #%s due to ST before threshold',
                                           block.blockheader.blocknumber)
                            logger.warning('Stake_selector: %s', block.blockheader.stake_selector)
                            logger.warning('epoch_blocknum: %s Threshold: %s',
                                           epoch_blocknum,
                                           threshold_blocknum - 1)
                            return False
                        stake_validators_list.set_first_hash(tx.txfrom, tx.first_hash)
                else:
                    stake_validators_list.add_next_sv(tx.txfrom, tx.hash, tx.first_hash, tx.balance)

            address_txn[tx.txfrom][0] += 1

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                address_txn[tx.txfrom][1] -= tx.amount

            if tx.subtype in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                address_txn[tx.txto][1] += tx.amount

            address_txn[tx.txfrom][2].append(pubhash)

        return True

    def commit(self, chain, block, address_txn):
        blocks_left = helper.get_blocks_left(block.blockheader.blocknumber)

        for address in address_txn:
            self.db.put(address, address_txn[address])

        if blocks_left == 1:
            logger.info('EPOCH change: resetting stake_list, activating next_stake_list, updating PRF with '
                        'seed+entropy updating wallet hashchains..')

            self.stake_validators_list.move_next_epoch()
            self.stake_list_put(self.stake_validators_list.to_json())

            hashchain(chain.my[0][1], epoch=block.blockheader.epoch + 1)
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
