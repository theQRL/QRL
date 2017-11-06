# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from _decimal import Decimal
from functools import reduce
from qrl.core import db, logger, config
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Transaction import Transaction, CoinBase
from qrl.core.StakeValidatorsList import StakeValidatorsList
from qrl.crypto.hashchain import hashchain
from qrl.core.Transaction_subtypes import TX_SUBTYPE_COINBASE, TX_SUBTYPE_TX, TX_SUBTYPE_STAKE, TX_SUBTYPE_DESTAKE
from pyqrllib.pyqrllib import bin2hstr
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2


class State:
    # FIXME: Rename to PersistentState
    # FIXME: Move blockchain caching/storage over here
    # FIXME: Improve key generation

    def __init__(self):
        """
        >>> State()._db is not None
        True
        >>> State().stake_validators_list is not None
        True
        """
        self._db = db.DB()  # generate db object here
        self.stake_validators_list = StakeValidatorsList()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._db is not None:
            del self._db
            self._db = None

    def stake_list_get(self):
        try:
            return self._db.get('stake_list')
        except KeyError:
            pass
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in stake_list_get')
            logger.exception(e)

        return []

    def stake_list_put(self, sl):
        try:
            self._db.put('stake_list', self.stake_validators_list.to_json())  # FIXME: to_json is missing
        except Exception as e:
            # FIXME: Review
            logger.warning("stake_list_put: %s %s", type(e), e)
            return False

    def put_epoch_seed(self, epoch_seed):
        try:
            self._db.put('epoch_seed', epoch_seed)
        except Exception as e:
            # FIXME: Review
            logger.exception(e)
            return False

    def get_epoch_seed(self):
        try:
            return self._db.get('epoch_seed')
        except Exception as e:
            # FIXME: Review
            logger.warning("get_epoch_seed: %s %s", type(e), e)
            return False

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    # Loads the state of the addresses mentioned into txn

    def uptodate(self, height):  # check state db marker to current blockheight.
        return height == self._blockheight()

    def _blockheight(self):
        return self._db.get('blockheight')

    def _set_blockheight(self, height):
        return self._db.put('blockheight', height)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    # Loads the state of the addresses mentioned into txn

    def nonce(self, addr: bytes):
        nonce, balance, pubhash_list = self.get_address(addr)
        return nonce

    def balance(self, addr: bytes):
        nonce, balance, pubhash_list = self.get_address(addr)
        return balance

    def pubhash(self, addr: bytes):
        nonce, balance, pubhash_list = self.get_address(addr)
        return pubhash_list

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def update_last_tx(self, block):
        if len(block.transactions) == 0:
            return
        last_txn = []

        try:
            last_txn = self._db.get('last_txn')
        except:
            pass

        for protobuf_txn in block.transactions[-20:]:
            txn = Transaction.from_pbdata(protobuf_txn)
            if txn.subtype == TX_SUBTYPE_TX:
                last_txn.insert(0, [txn.to_json(),
                                    block.block_number,
                                    block.timestamp])

        del last_txn[20:]
        self._db.put('last_txn', last_txn)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def update_address_tx_hashes(self, addr: bytes, new_txhash: bytes):
        txhash = self.get_address_tx_hashes(addr)
        txhash.append(bin2hstr(new_txhash))
        self._db.put(b'txn_' + addr, txhash)

    def get_address_tx_hashes(self, addr: bytes):
        try:
            txhash = self._db.get(b'txn_' + addr)
        except KeyError:
            txhash = []
        except Exception as e:
            logger.exception(e)
            txhash = []

        return txhash

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def get_txn_count(self, addr):
        try:
            return self._db.get((b'txn_count_' + addr))
        except KeyError:
            pass
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in get_txn_count')
            logger.exception(e)

        return 0

    def increase_txn_count(self, addr: bytes):
        # FIXME: This should be transactional
        last_count = self.get_txn_count(addr)
        self._db.put(b'txn_count_' + addr, last_count + 1)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def update_tx_metadata(self, block):
        if len(block.transactions) == 0:
            return

        # FIXME: Inconsistency in the keys/types
        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            if txn.subtype in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
                self._db.put(bin2hstr(txn.txhash),
                             [txn.to_json(),
                              block.block_number,
                              block.timestamp])

                if txn.subtype == TX_SUBTYPE_TX:
                    self.update_address_tx_hashes(txn.txfrom, txn.txhash)

                self.update_address_tx_hashes(txn.txto, txn.txhash)
                self.increase_txn_count(txn.txto)
                self.increase_txn_count(txn.txfrom)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def _get_address_state(self, address: bytes):
        address_state = qrl_pb2.AddressState()
        data = self._db.get_raw(address)
        if data is None:
            raise KeyError("{} not found".format(address))

        address_state.ParseFromString(bytes(data))

        # FIXME: pubhashes is deserialized as a pb container but some methods want to make changes. Workaround
        tmp = [h for h in address_state.pubhashes]

        return [address_state.nonce,
                address_state.balance,
                tmp]

    def _save_address_state(self, address: bytes, state):
        # FIXME: internally keep data in byte form
        address_state = qrl_pb2.AddressState()
        address_state.address = address
        address_state.nonce = state[0]
        address_state.balance = state[1]

        # FIXME: Keep internally all hashes as bytearrays
        address_state.pubhashes.extend([bytes(b) for b in state[2]])

        self._db.put_raw(address, address_state.SerializeToString())

    def get_address(self, address: bytes):
        # FIXME: Avoid two calls to know if address is not recognized (merged with is used)
        try:
            return self._get_address_state(address)
        except KeyError:
            # FIXME: Check all cases where address is not found
            return [config.dev.default_nonce, config.dev.default_account_balance, []]

    def address_used(self, address: bytes):
        # FIXME: Probably obsolete
        try:
            return self._get_address_state(address)
        except KeyError:
            return False
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in address_used')
            logger.exception(e)
            raise

    def return_all_addresses(self):
        addresses = []
        address_state = qrl_pb2.AddressState()
        for k, v in self._db.RangeIter(b'Q', b'Qz'):
            address_state.ParseFromString(v)
            addresses.append([k, Decimal(address_state.balance)])  # FIXME: Why Decimal?
        return addresses

    def zero_all_addresses(self):
        for k, v in self._db.RangeIter(b'Q', b'Qz'):
            self._db.delete(k)
        logger.info('Reset Finished')
        self._set_blockheight(0)
        return

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def total_coin_supply(self):
        # FIXME: This is temporary code. NOT SCALABLE. It is easy to keep a global count
        coins = Decimal(0)
        address_state = qrl_pb2.AddressState()
        for k, v in self._db.RangeIter(b'Q', b'Qz'):
            address_state.ParseFromString(v)
            coins = coins + Decimal(address_state.balance)  # FIXME: decimal math?
        return coins

    @staticmethod
    def calc_seed(sl, verbose=False):
        # FIXME: Does this belong here?
        if verbose:
            logger.info('stake_list --> ')
            for s in sl:
                logger.info('%s %s', s[0], s[3])

        epoch_seed = 0

        for staker in sl:
            epoch_seed |= int(str(bin2hstr(tuple(staker[1]))), 16)

        return epoch_seed

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    # FIXME: Remove from state

    def _update_genesis(self, buffered_chain, block, address_txn) -> bool:
        # FIXME: This does not seem to be related to persistance
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
        # FIXME: Most of this should be done in the GenesisBlock which should derive from Block
        genesis_info = GenesisBlock.load_genesis_info()

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
                self.stake_validators_list.add_sv(genesis_info[tx.txfrom], tx, 1)

                address_txn[tx.txfrom][2].append(tx.pubhash)

        epoch_seed = self.stake_validators_list.calc_seed()
        buffered_chain.epoch_seed = epoch_seed
        self.put_epoch_seed(epoch_seed)

        buffered_chain.epoch_seed = self.calc_seed(tmp_list)

        # FIXME: Move score to an appropriate place
        buffered_chain.stake_list = sorted(tmp_list,
                                           key=lambda staker:
                                           buffered_chain._chain.score(stake_address=staker[0],
                                                                       reveal_one=bin2hstr(
                                                                           sha256(str(
                                                                               reduce(lambda set1,
                                                                                             set2: set1 + set2,
                                                                                      tuple(staker[
                                                                                                1]))).encode())),
                                                                       balance=staker[3],
                                                                       seed=buffered_chain.block_chain_buffer.epoch_seed))

        # FIXME: Changes the type in the same variable!
        buffered_chain.epoch_seed = format(buffered_chain.epoch_seed, 'x')

        if buffered_chain._chain.stake_list[0][0] != block.stake_selector:
            logger.info('stake selector wrong..')
            return False

        xmss = buffered_chain.wallet.address_bundle[0].xmss
        tmphc = hashchain(xmss.get_seed_private(), epoch=0)  # FIXME: Risky use of xmss

        buffered_chain.hash_chain = tmphc.hashchain
        buffered_chain.wallet.save_wallet()
        return True

    def update(self, block, stake_validators_list, address_txn) -> bool:
        # FIXME: remove from state and move to another place
        # reminder contents: (state address -> nonce, balance, [pubhash]) (stake -> address, hash_term, nonce)

        if block.stake_selector not in stake_validators_list.sv_list:
            logger.warning('stake selector not in stake_list_get')
            return False

        if stake_validators_list.sv_list[block.stake_selector].is_banned:
            logger.warning('stake selector is in banned list')
            return False

        if not stake_validators_list.sv_list[block.stake_selector].is_active:
            logger.warning('stake selector is in inactive')
            return False

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

                if tx.txfrom in stake_validators_list.sv_list:
                    expiry = stake_validators_list.sv_list[
                                 tx.txfrom].activation_blocknumber + config.dev.blocks_per_epoch

                    if tx.activation_blocknumber < expiry:
                        logger.warning('Failed %s is already active for the given range', tx.txfrom)
                        return False

                    activation_limit = block.block_number + config.dev.blocks_per_epoch + 1

                    if tx.activation_blocknumber > activation_limit:
                        logger.warning('Failed %s activation_blocknumber beyond limit', tx.txfrom)
                        logger.warning('Found %s', tx.activation_blocknumber)
                        logger.warning('Must be less than %s', tx.activation_limit)
                        return False

                future_stake_addresses = stake_validators_list.future_stake_addresses

                if tx.txfrom not in future_stake_addresses:
                    if tx.txfrom in address_txn:
                        balance = address_txn[tx.txfrom][1]
                    else:
                        balance = self._get_address_state(tx.txfrom)[1]
                    stake_validators_list.add_sv(balance, tx, block.block_number)

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
