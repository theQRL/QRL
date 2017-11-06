# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from _decimal import Decimal

from pyqrllib.pyqrllib import bin2hstr

from qrl.core import db, logger, config
from qrl.core.StakeValidatorsList import StakeValidatorsList
from qrl.core.Transaction import Transaction
from qrl.core.Transaction_subtypes import TX_SUBTYPE_COINBASE, TX_SUBTYPE_TX, TX_SUBTYPE_STAKE, TX_SUBTYPE_DESTAKE
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
