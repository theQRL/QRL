# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import yaml
import os

from _decimal import Decimal
from functools import reduce
from qrl.core import db, logger, config, helper
from qrl.core.Transaction import Transaction, CoinBase
from qrl.core.StakeValidatorsList import StakeValidatorsList
from qrl.crypto.hashchain import hashchain
from qrl.core.Transaction_subtypes import TX_SUBTYPE_COINBASE, TX_SUBTYPE_TX, TX_SUBTYPE_STAKE, TX_SUBTYPE_DESTAKE
from pyqrllib.pyqrllib import bin2hstr
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2


class State:
    """
        state functions
        first iteration - state data stored in leveldb file
        state holds address balances, the transaction nonce and a list of
        pubhash keys used for each tx - to prevent key reuse.
    """

    def __init__(self):
        """
        >>> State().db is not None
        True
        >>> State().stake_validators_list is not None
        True
        """
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
            pass
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in stake_list_get')
            logger.exception(e)

        return []

    def stake_list_put(self, sl):
        try:
            self.db.put('stake_list', self.stake_validators_list.to_json())
        except Exception as e:
            # FIXME: Review
            logger.warning("stake_list_put: %s %s", type(e), e)
            return False

    def put_epoch_seed(self, epoch_seed):
        try:
            self.db.put('epoch_seed', epoch_seed)
        except Exception as e:
            # FIXME: Review
            logger.exception(e)
            return False

    def get_epoch_seed(self):
        try:
            return self.db.get('epoch_seed')
        except Exception as e:
            # FIXME: Review
            logger.warning("get_epoch_seed: %s %s", type(e), e)
            return False

    def uptodate(self, height):  # check state db marker to current blockheight.
        return height == self._blockheight()

    def _blockheight(self):
        return self.db.get('blockheight')

    def _set_blockheight(self, height):
        return self.db.put('blockheight', height)

    def get_txn_count(self, addr):
        try:
            return self.db.get((b'txn_count_' + addr))
        except KeyError:
            pass
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in get_txn_count')
            logger.exception(e)

        return 0

    def get_address(self, address):
        try:
            return self._get_address_state(address)
        except KeyError:
            # FIXME: Check all cases where address is not found
            return [config.dev.default_nonce, config.dev.default_account_balance, config.dev.default_pubhash_blacklist]

    def address_used(self, address):
        try:
            return self._get_address_state(address)
        except KeyError:
            return False
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in address_used')
            logger.exception(e)
            raise

    def nonce(self, addr):
        nonce, balance, pubhash_list = self.get_address(addr)
        return nonce

    def balance(self, addr):
        nonce, balance, pubhash_list = self.get_address(addr)
        return balance

    def pubhash(self, addr):
        nonce, balance, pubhash_list = self.get_address(addr)
        return pubhash_list

    def hrs(self, hrs):
        try:
            return self.db.get('hrs{}'.format(hrs))
        except KeyError:
            pass
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in State.hrs()')
            logger.exception(e)

        return False

    def validate_tx_pool(self, chain):
        result = True

        for tx in chain.transaction_pool:
            block_chain_buffer = chain.block_chain_buffer
            tx_state = block_chain_buffer.get_stxn_state(blocknumber=block_chain_buffer.height() + 1,
                                                         addr=tx.txfrom)
            if not tx.validate_extended(tx_state=tx_state):
                result = False
                logger.warning('tx %s failed', tx.txhash)
                chain.remove_tx_from_pool(tx)

        return result

    def add_block(self, chain, block, ignore_save_wallet=False):
        address_txn = dict()
        self.load_address_state(chain, block, address_txn)  # FIXME: Bottleneck

        if block.blockheader.blocknumber == 1:
            if not self.update_genesis(chain, block, address_txn):
                return False
            self.commit(chain, block, address_txn, ignore_save_wallet=ignore_save_wallet)
            return True

        blocks_left = helper.get_blocks_left(block.blockheader.blocknumber)
        nonce = self.stake_validators_list.sv_list[block.transactions[0].addr_from].nonce
        logger.debug('BLOCK: %s epoch: %s blocks_left: %s nonce: %s stake_selector %s',
                    block.blockheader.blocknumber,
                    block.blockheader.epoch,
                    blocks_left - 1,
                    nonce,
                    block.blockheader.stake_selector)

        if not self.update(block, self.stake_validators_list, address_txn):
            return

        self.commit(chain, block, address_txn, ignore_save_wallet=ignore_save_wallet)  # FIXME: Bottleneck

        return True

    # Loads the state of the addresses mentioned into txn
    def load_address_state(self, chain, block, address_txn):
        blocknumber = block.blockheader.blocknumber

        for protobuf_tx in block.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.txfrom not in address_txn:
                address_txn[tx.txfrom] = chain.block_chain_buffer.get_stxn_state(blocknumber, tx.txfrom)

            if tx.subtype in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
                if tx.txto not in address_txn:
                    address_txn[tx.txto] = chain.block_chain_buffer.get_stxn_state(blocknumber, tx.txto)

        return address_txn

    def update_genesis(self, chain, block, address_txn):
        # Start Updating coin base txn
        protobuf_tx = block.transactions[0]  # Expecting only 1 txn of COINBASE subtype in genesis block
        tx = CoinBase.from_pbdata(protobuf_tx)
        if tx.nonce != 1:
            logger.warning('nonce incorrect, invalid tx')
            logger.warning('subtype: %s', tx.subtype)
            logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, address_txn[tx.txfrom][0] + 1)
            return False
        # TODO: To be fixed later
        if tx.pubhash in address_txn[tx.txfrom][2]:
            logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
            logger.warning('subtype: %s', tx.subtype)
            return False

        address_txn[tx.txto][1] += tx.amount
        address_txn[tx.txfrom][2].append(tx.pubhash)

        # Coinbase update end here
        genesis_info = self.load_genesis_info()

        tmp_list = []
        for protobuf_tx in block.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.subtype == TX_SUBTYPE_STAKE:
                # update txfrom, hash and stake_nonce against genesis for current or next stake_list
                tmp_list.append([tx.txfrom,
                                 tx.hash,
                                 0,
                                 genesis_info[tx.txfrom],
                                 tx.slave_public_key])

                if tx.txfrom not in genesis_info:
                    logger.warning('designated staker not in genesis..')
                    return False

                # FIX ME: This goes to stake validator list without verifiction, Security Risk
                self.stake_validators_list.add_sv(tx, 1)

                address_txn[tx.txfrom][2].append(tx.pubhash)

        epoch_seed = self.stake_validators_list.calc_seed()
        chain.block_chain_buffer.epoch_seed = epoch_seed
        self.put_epoch_seed(epoch_seed)

        chain.block_chain_buffer.epoch_seed = chain.state.calc_seed(tmp_list)
        chain.stake_list = sorted(tmp_list,
                                  key=lambda staker: chain.score(stake_address=staker[0],
                                                                 reveal_one=bin2hstr(sha256(str(
                                                                     reduce(lambda set1, set2: set1 + set2,
                                                                            tuple(staker[1]))).encode())),
                                                                 balance=staker[3],
                                                                 seed=chain.block_chain_buffer.epoch_seed))
        chain.block_chain_buffer.epoch_seed = format(chain.block_chain_buffer.epoch_seed, 'x')
        if chain.stake_list[0][0] != block.blockheader.stake_selector:
            logger.info('stake selector wrong..')
            return

        xmss = chain.wallet.address_bundle[0].xmss
        tmphc = hashchain(xmss.get_seed_private(), epoch=0)

        chain.hash_chain = tmphc.hashchain
        chain.wallet.save_wallet()
        return True

    def update(self, block, stake_validators_list, address_txn):

        # reminder contents: (state address -> nonce, balance, [pubhash]) (stake -> address, hash_term, nonce)

        if block.blockheader.stake_selector not in stake_validators_list.sv_list:
            logger.warning('stake selector not in stake_list_get')
            return

        if stake_validators_list.sv_list[block.blockheader.stake_selector].is_banned:
            logger.warning('stake selector is in banned list')
            return

        if not stake_validators_list.sv_list[block.blockheader.stake_selector].is_active:
            logger.warning('stake selector is in inactive')
            return

        # FIX ME : Temporary fix, to include only either ST txn or TransferCoin txn for an address
        stake_txn = set()
        transfercoin_txn = set()
        destake_txn = set()

        # cycle through every tx in the new block to check state
        for protobuf_tx in block.transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if tx.subtype == TX_SUBTYPE_COINBASE:
                expected_nonce = stake_validators_list.sv_list[tx.txfrom].nonce + 1
            else:
                expected_nonce = address_txn[tx.txfrom][0] + 1
            if tx.nonce != expected_nonce:
                logger.warning('nonce incorrect, invalid tx')
                logger.warning('subtype: %s', tx.subtype)
                logger.warning('%s actual: %s expected: %s', tx.txfrom, tx.nonce, expected_nonce)
                return False
            # TODO: To be fixed later
            if tx.pubhash in address_txn[tx.txfrom][2]:
                logger.warning('pubkey reuse detected: invalid tx %s', tx.txhash)
                logger.warning('subtype: %s', tx.subtype)
                return False

            if tx.subtype == TX_SUBTYPE_TX:
                if tx.txfrom in stake_txn:
                    logger.warning("Transfer coin done by %s address is a Stake Validator", tx.txfrom)
                    return False

                if tx.txfrom in stake_validators_list.sv_list and stake_validators_list.sv_list[tx.txfrom].is_active:
                    logger.warning("Source address is a Stake Validator, balance is locked while staking")
                    return False

                if (tx.txfrom in stake_validators_list.future_stake_addresses and
                        stake_validators_list.future_stake_addresses[tx.txfrom].is_active):
                    logger.warning("Source address is in Future Stake Validator List, balance is locked")
                    return False

                if address_txn[tx.txfrom][1] - tx.amount < 0:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s', address_txn[tx.txfrom][1], tx.amount)
                    return False

                transfercoin_txn.add(tx.txfrom)

            elif tx.subtype == TX_SUBTYPE_STAKE:
                if tx.txfrom in transfercoin_txn:
                    logger.warning('Block cannot have both st txn & transfer coin txn from same address %s', tx.txfrom)
                    return False
                if tx.txfrom in stake_txn:
                    logger.warning('Block cannot have multiple Stake Txn from same address %s', tx.txfrom)
                    return False
                if tx.txfrom in destake_txn:
                    logger.warning('Block may not have both Stake and Destake txn of same address %s', tx.txfrom)
                    return False

                address_txn[tx.txfrom][2].append(tx.pubhash)

                if tx.txfrom in stake_validators_list.sv_list:
                    expiry = stake_validators_list.sv_list[tx.txfrom].activation_blocknumber + config.dev.blocks_per_epoch

                    if tx.activation_blocknumber < expiry:
                        logger.warning('Failed %s is already active for the given range', tx.txfrom)
                        return False

                    activation_limit = block.blockheader.blocknumber + config.dev.blocks_per_epoch + 1

                    if tx.activation_blocknumber > activation_limit:
                        logger.warning('Failed %s activation_blocknumber beyond limit', tx.txfrom)
                        logger.warning('Found %s', tx.activation_blocknumber)
                        logger.warning('Must be less than %s', tx.activation_limit)
                        return False

                future_stake_addresses = stake_validators_list.future_stake_addresses

                if tx.txfrom not in future_stake_addresses:
                    stake_validators_list.add_sv(tx, block.blockheader.blocknumber)

                stake_txn.add(tx.txfrom)

            elif tx.subtype == TX_SUBTYPE_DESTAKE:
                if tx.txfrom in stake_txn:
                    logger.warning('Block may not have both Destake and Stake txn of same address %s', tx.txfrom)
                    return False

                if tx.txfrom in destake_txn:
                    logger.warning('Block cannot have multiple Destake Txn from same address %s', tx.txfrom)
                    return False

                if tx.txfrom not in stake_validators_list.sv_list and tx.txfrom not in stake_validators_list.future_stake_addresses:
                    logger.warning('Failed due to destake %s is not a stake validator', tx.txfrom)
                    return False

                if tx.txfrom in stake_validators_list.sv_list:
                    stake_validators_list.sv_list[tx.txfrom].is_active = False

                if tx.txfrom in stake_validators_list.future_stake_addresses:
                    stake_validators_list.future_stake_addresses[tx.txfrom].is_active = False

                destake_txn.add(tx.txfrom)

            if tx.subtype != TX_SUBTYPE_COINBASE:
                address_txn[tx.txfrom][0] += 1

            if tx.subtype == TX_SUBTYPE_TX:
                address_txn[tx.txfrom][1] -= tx.amount - tx.fee

            if tx.subtype in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
                address_txn[tx.txto][1] += tx.amount

            address_txn[tx.txfrom][2].append(tx.pubhash)

        return True

    def _get_address_state(self, address):
        address_state = qrl_pb2.AddressState()
        data = self.db.get_raw(address)
        if data is None:
            raise KeyError("{} not found".format(address))

        address_state.ParseFromString(bytes(data))

        # FIXME: pubhashes is deserialized as a pb container but some methods want to make changes. Workaround
        tmp = [h for h in address_state.pubhashes]

        return [address_state.nonce,
                address_state.balance,
                tmp]

    def _save_address_state(self, address, state):
        # FIXME: internally keep data in byte form
        address_state = qrl_pb2.AddressState()
        address_state.address = address
        address_state.nonce = state[0]
        address_state.balance = state[1]

        # FIXME: Keep internally all hashes as bytearrays
        address_state.pubhashes.extend([bytes(b) for b in state[2]])

        self.db.put_raw(address, address_state.SerializeToString())

    def return_all_addresses(self):
        addresses = []
        address_state = qrl_pb2.AddressState()
        for k, v in self.db.RangeIter(b'Q', b'Qz'):
            address_state.ParseFromString(v)
            addresses.append([k, Decimal(address_state.balance)])
        return addresses

    def zero_all_addresses(self):
        for k, v in self.db.RangeIter(b'Q', b'Qz'):
            self.db.delete(k)
        logger.info('Reset Finished')
        self._set_blockheight(0)
        return

    def total_coin_supply(self):
        # FIXME: This is temporary code. NOT SCALABLE. It is easy to keep a global count
        coins = Decimal(0)
        address_state = qrl_pb2.AddressState()
        for k, v in self.db.RangeIter(b'Q', b'Qz'):
            address_state.ParseFromString(v)
            coins = coins + Decimal(address_state.balance)  # FIXME: decimal math?
        return coins

    def commit(self, chain, block, address_txn, ignore_save_wallet=False):

        # FIXME: This indexing approach is very inefficient
        blocks_left = helper.get_blocks_left(block.blockheader.blocknumber)

        staker = block.blockheader.stake_selector
        self.stake_validators_list.sv_list[staker].nonce += 1

        for address in address_txn:
            self._save_address_state(address, address_txn[address])

        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in self.stake_validators_list.sv_list:
                self.stake_validators_list.sv_list[dup_tx.coinbase1.txto].is_banned = True

        if blocks_left == 1:
            logger.info('EPOCH change:  updating PRF with updating wallet hashchains..')

            xmss = chain.wallet.address_bundle[0].xmss
            tmphc = hashchain(xmss.get_seed_private(), epoch=block.blockheader.epoch + 1)

            chain.hash_chain = tmphc.hashchain

        if not ignore_save_wallet:
            chain.wallet.save_wallet()

        self._set_blockheight(chain.height() + 1)

        self.stake_validators_list.update_sv(block.blockheader.blocknumber)

        logger.debug('%s %s tx passed verification.', bin2hstr(block.blockheader.headerhash), len(block.transactions))
        return True

    def calc_seed(self, sl, verbose=False):
        if verbose:
            logger.info('stake_list --> ')
            for s in sl:
                logger.info('%s %s', s[0], s[3])

        epoch_seed = 0

        for staker in sl:
            epoch_seed |= int(str(bin2hstr(tuple(staker[1]))), 16)

        return epoch_seed

    @staticmethod
    def load_genesis_info():
        genesis_info = dict()
        package_directory = os.path.dirname(os.path.abspath(__file__))
        genesis_data_path = os.path.join(package_directory, 'genesis.yml')

        with open(genesis_data_path) as f:
            logger.info("Loading genesis from %s", genesis_data_path)
            data_map = yaml.safe_load(f)
            for key in data_map['genesis_info']:
                genesis_info[key.encode()] = data_map['genesis_info'][key] * (10**8)

        return genesis_info

    def read_genesis(self):
        logger.info('genesis:')

        genesis_info = self.load_genesis_info()

        for address in genesis_info:
            self._save_address_state(address, [0, genesis_info[address], []])
        return True

    def read_chain(self, chain):

        self.zero_all_addresses()
        c = chain.m_get_block(0).state
        for address in c:
            self._save_address_state(address[0], address[1])

        c = chain.m_read_chain()[2:]
        for block in c:

            # update coinbase address state
            stake_master = self.get_address(block.blockheader.stake_selector)
            stake_master[1] += block.transactions[0].amount
            self.db.put(block.blockheader.stake_selector, stake_master)

            for tx in block.transactions:
                pubhash = tx.pubhash

                nonce1, balance1, pubhash_list1 = self.get_address(tx.txfrom)

                # FIXME: review this.. why stake transaction are getting here?
                if hasattr(tx, 'amount') and balance1 - tx.amount < 0:
                    logger.info('%s %s exceeds balance, invalid tx %s', tx, tx.txfrom, tx.txhash)
                    logger.info('failed state checks %s', bin2hstr(block.blockheader.headerhash))
                    return False

                if tx.nonce != nonce1 + 1:
                    logger.info('nonce incorrect, invalid tx %s', bin2hstr(tx.txhash))
                    logger.info('%s failed state checks', bin2hstr(block.blockheader.headerhash))
                    return False
                # TODO: To be fixed later
                if pubhash in pubhash_list1:
                    logger.info('public key re-use detected, invalid tx %s', bin2hstr(tx.txhash))
                    logger.info('failed state checks %s', bin2hstr(block.blockheader.headerhash))
                    return False

                # Update state address from
                nonce1 += 1
                balance1 = balance1 - tx.amount
                pubhash_list1.append(pubhash)
                self._save_address_state(tx.txfrom, [nonce1, balance1,
                                                     pubhash_list1])  # must be ordered in case tx.txfrom = tx.txto

                # Update state address to
                nonce2, balance2, pubhash_list2 = self.get_address(tx.txto)
                balance2 = balance2 + tx.amount

                self._save_address_state(tx.txto, [nonce2, balance2, pubhash_list2])

            logger.info((block, str(len(block.transactions)), 'tx ', ' passed'))

        self._set_blockheight(chain.m_blockheight())
        return True
