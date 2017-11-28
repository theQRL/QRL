# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import List

from pyqrllib.pyqrllib import bin2hstr, hstr2bin

from qrl.core import db, logger, config
from qrl.core.AddressState import AddressState
from qrl.core.StakeValidatorsTracker import StakeValidatorsTracker
from qrl.core.Transaction import Transaction
from qrl.generated import qrl_pb2


class State:
    # FIXME: Rename to PersistentState
    # FIXME: Move blockchain caching/storage over here
    # FIXME: Improve key generation

    def __init__(self):
        self._db = db.DB()  # generate db object here

        # FIXME: Move to BufferedChain
        self.stake_validators_tracker = StakeValidatorsTracker()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._db is not None:
            del self._db
            self._db = None

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

    def get_lattice_public_key(self, address):
        try:
            return set(self._db.get(b'lattice_' + address))
        except KeyError:
            return set()
        except Exception as e:
            logger.exception(e)
            return False

    def put_lattice_public_key(self, lattice_public_key_txn):
        address = lattice_public_key_txn.txfrom
        lattice_public_keys = self.get_lattice_public_key(address)
        lattice_public_keys.add(lattice_public_key_txn.kyber_pk)
        self._db.put(b'lattice_' + address, list(lattice_public_keys))

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def uptodate(self, height):  # check state db marker to current blockheight.
        # FIXME: Remove
        return height == self._blockheight()

    def _blockheight(self):
        # FIXME: Remove
        return self._db.get('blockheight')

    def _set_blockheight(self, height):
        # FIXME: Remove
        return self._db.put('blockheight', height)

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
        except:  # noqa
            pass

        for protobuf_txn in block.transactions[-20:]:
            txn = Transaction.from_pbdata(protobuf_txn)
            if txn.subtype == qrl_pb2.Transaction.TRANSFER:
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
        txhash.append(new_txhash)

        # FIXME:  Json does not support bytes directly | Temporary workaround
        tmp_hashes = [bin2hstr(item) for item in txhash]

        self._db.put(b'txn_' + addr, tmp_hashes)

    def update_stake_validators(self, stake_validators_tracker: StakeValidatorsTracker):
        self.stake_validators_tracker = stake_validators_tracker

    def get_address_tx_hashes(self, addr: bytes) -> List[bytes]:
        try:
            tx_hashes = self._db.get(b'txn_' + addr)
        except KeyError:
            tx_hashes = []
        except Exception as e:
            logger.exception(e)
            tx_hashes = []

        tx_hashes = [bytes(hstr2bin(item)) for item in tx_hashes]

        return tx_hashes

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
            if txn.subtype in (qrl_pb2.Transaction.TRANSFER, qrl_pb2.Transaction.COINBASE):
                self._db.put(bin2hstr(txn.txhash),
                             [txn.to_json(),
                              block.block_number,
                              block.timestamp])

                if txn.subtype == qrl_pb2.Transaction.TRANSFER:
                    self.update_address_tx_hashes(txn.txfrom, txn.txhash)

                self.update_address_tx_hashes(txn.txto, txn.txhash)
                self.increase_txn_count(txn.txto)
                self.increase_txn_count(txn.txfrom)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def _get_address_state(self, address: bytes) -> AddressState:
        data = self._db.get_raw(address)
        if data is None:
            raise KeyError("{} not found".format(address))
        pbdata = qrl_pb2.AddressState()
        pbdata.ParseFromString(bytes(data))
        address_state = AddressState(pbdata)
        return address_state

    def _save_address_state(self, address_state: AddressState):
        data = address_state.pbdata.SerializeToString()
        self._db.put_raw(address_state.address, data)

    def get_address(self, address: bytes) -> AddressState:
        # FIXME: Avoid two calls to know if address is not recognized (merged with is used)
        try:
            return self._get_address_state(address)
        except KeyError:
            # FIXME: Check all cases where address is not found
            return AddressState.create(address=address,
                                       nonce=config.dev.default_nonce,
                                       balance=config.dev.default_account_balance,
                                       pubhashes=[])

    def nonce(self, addr: bytes) -> int:
        return self.get_address(addr).nonce

    def balance(self, addr: bytes) -> int:
        return self.get_address(addr).balance

    def pubhash(self, addr: bytes):
        return self.get_address(addr).pubhashes

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
        for key, data in self._db.RangeIter(b'Q', b'Qz'):
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            addresses.append(address_state)
        return addresses

    def zero_all_addresses(self):
        for k, v in self._db.RangeIter(b'Q', b'Qz'):
            self._db.delete(k)
        logger.info('Reset Finished')
        self._set_blockheight(0)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def total_coin_supply(self):
        # FIXME: This is temporary code. NOT SCALABLE. It is easy to keep a global count
        all_addresses = self.return_all_addresses()
        coins = 0
        for a in all_addresses:
            coins = coins + a.balance
        return coins
