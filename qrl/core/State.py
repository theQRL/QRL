# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from copy import deepcopy
from typing import List
from pyqrllib.pyqrllib import bin2hstr, hstr2bin

from qrl.core import db, logger, config
from qrl.core.AddressState import AddressState
from qrl.core.TokenMetadata import TokenMetadata
from qrl.core.TokenList import TokenList
from qrl.core.StakeValidatorsTracker import StakeValidatorsTracker
from qrl.core.Transaction import Transaction, TokenTransaction, TransferTokenTransaction
from qrl.generated import qrl_pb2


class State:
    # FIXME: Rename to PersistentState
    # FIXME: Move blockchain caching/storage over here
    # FIXME: Improve key generation

    def __init__(self):
        self._db = db.DB()  # generate db object here

        # FIXME: Move to BufferedChain
        self.prev_stake_validators_tracker = StakeValidatorsTracker()
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

    def update_last_tx(self, block, batch):
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
        self._db.put('last_txn', last_txn, batch)

    def get_last_txs(self):
        try:
            last_txn = self._db.get('last_txn')
        except:  # noqa
            return []

        txs = []
        for tx_metadata in last_txn:
            tx_json, block_num, block_ts = tx_metadata
            tx = Transaction.from_json(tx_json)
            txs.append(tx)

        return txs

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

    def get_token_list(self):
        try:
            return self._db.get_raw(b'token_list')
        except KeyError:
            return TokenList().to_json()

    def update_token_list(self, token_txhashes: list, batch):
        pbdata = self.get_token_list()
        token_list = TokenList.from_json(pbdata)
        token_list.update(token_txhashes)
        self._db.put_raw(b'token_list', token_list.to_json().encode(), batch)

    def get_token_metadata(self, token_txhash: bytes):
        json_data = self._db.get_raw(b'token_'+token_txhash)
        return TokenMetadata.from_json(json_data)

    def update_token_metadata(self, transfer_token: TransferTokenTransaction):
        token_metadata = self.get_token_metadata(transfer_token.token_txhash)
        token_metadata.update([transfer_token.txhash])
        self._db.put_raw(b'token_'+transfer_token.token_txhash,
                         token_metadata.to_json().encode())

    def create_token_metadata(self, token: TokenTransaction):
        token_metadata = TokenMetadata.create(token_txhash=token.txhash, transfer_token_txhashes=[token.txhash])
        self._db.put_raw(b'token_'+token.txhash,
                         token_metadata.to_json().encode())

    def update_stake_validators(self, stake_validators_tracker: StakeValidatorsTracker):
        self.prev_stake_validators_tracker = self.stake_validators_tracker
        self.stake_validators_tracker = stake_validators_tracker

    def get_stake_validators_tracker(self):
        return self._db.get_raw(b'stake_validators_tracker')

    def write_stake_validators_tracker(self, batch):
        self._db.put_raw(b'stake_validators_tracker', self.stake_validators_tracker.to_json().encode(), batch)

    def get_prev_stake_validators_tracker(self):
        return self._db.get_raw(b'prev_stake_validators_tracker')

    def write_prev_stake_validators_tracker(self, batch):
        self._db.put_raw(b'prev_stake_validators_tracker', self.prev_stake_validators_tracker.to_json().encode(), batch)

    def get_next_seed(self):
        return self._db.get_raw(b'next_seed')

    def update_next_seed(self, next_seed, batch):
        self._db.put_raw(b'next_seed', next_seed, batch)

    def get_state_version(self):
        return self._db.get(b'state_version')

    def update_state_version(self, block_number, batch):
        self._db.put(b'state_version', block_number, batch)

    def get_slave_xmss(self):
        return self._db.get(b'slave_xmss')

    def update_slave_xmss(self, slave_xmss, batch):
        if slave_xmss is None:
            self._db.put(b'slave_xmss', None, batch)
        else:
            self._db.put(b'slave_xmss', [slave_xmss.get_index(), slave_xmss.get_seed()], batch)

    def get_block(self, block_number):
        return self._db.get_raw(str(block_number).encode())

    def put_block(self, block, batch):
        self._db.put_raw(str(block.block_number).encode(), block.to_json().encode(), batch)

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

    def update_tx_metadata(self, block, batch):
        if len(block.transactions) == 0:
            return

        token_list = []

        # FIXME: Inconsistency in the keys/types
        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            if txn.subtype in (qrl_pb2.Transaction.TRANSFER,
                               qrl_pb2.Transaction.COINBASE,
                               qrl_pb2.Transaction.MESSAGE,
                               qrl_pb2.Transaction.TOKEN,
                               qrl_pb2.Transaction.TRANSFERTOKEN):

                self._db.put(bin2hstr(txn.txhash),
                             [txn.to_json(), block.block_number, block.timestamp],
                             batch)

                if txn.subtype in (qrl_pb2.Transaction.TRANSFER,
                                   qrl_pb2.Transaction.MESSAGE,
                                   qrl_pb2.Transaction.TOKEN,
                                   qrl_pb2.Transaction.TRANSFERTOKEN):
                    # FIXME: Being updated without batch, need to fix,
                    # as its making get request, and batch get not possible
                    # Thus cache is required to have only 1 time get
                    self.update_address_tx_hashes(txn.txfrom, txn.txhash)

                    if txn.subtype == qrl_pb2.Transaction.TOKEN:
                        self.update_address_tx_hashes(txn.owner, txn.txhash)
                        for initial_balance in txn.initial_balances:
                            if initial_balance.address == txn.owner:
                                continue
                            self.update_address_tx_hashes(initial_balance.address, txn.txhash)

                if txn.subtype in (qrl_pb2.Transaction.TRANSFER,
                                   qrl_pb2.Transaction.COINBASE,
                                   qrl_pb2.Transaction.TRANSFERTOKEN):
                    # FIXME: Being updated without batch, need to fix,
                    if txn.subtype == qrl_pb2.Transaction.TRANSFERTOKEN:
                        self.update_token_metadata(txn)
                    self.update_address_tx_hashes(txn.txto, txn.txhash)
                    self.increase_txn_count(txn.txto)

                if txn.subtype == qrl_pb2.Transaction.TOKEN:
                    self.create_token_metadata(txn)
                    token_list.append(txn.txhash)

                self.increase_txn_count(txn.txfrom)

        if token_list:
            self.update_token_list(token_list, batch)

    def get_tx_metadata(self, txhash: bytes):
        try:
            tx_metadata = self._db.get(bin2hstr(txhash))
        except Exception:
            return None
        if tx_metadata is None:
            return None
        txn_json, block_number, _ = tx_metadata
        return Transaction.from_json(txn_json), block_number

    def update_vote_metadata(self, block, batch):
        if len(block.transactions) == 0:
            return
        if block.block_number == 1:
            self.prev_stake_validators_tracker = deepcopy(self.stake_validators_tracker)

        total_stake_amount = self.prev_stake_validators_tracker.get_total_stake_amount()
        voted_weight = 0
        # FIXME: Inconsistency in the keys/types
        for protobuf_txn in block.vote:
            vote = Transaction.from_pbdata(protobuf_txn)
            voted_weight += self.prev_stake_validators_tracker.get_stake_balance(vote.txfrom)

        self._db.put(b'vote_'+str(block.block_number).encode(),
                     [voted_weight,
                      total_stake_amount], batch)

    def get_vote_metadata(self, blocknumber: int):
        try:
            return self._db.get(b'vote_'+str(blocknumber).encode())
        except Exception:
            return None

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

    def _save_address_state(self, address_state: AddressState, batch=None):
        data = address_state.pbdata.SerializeToString()
        self._db.put_raw(address_state.address, data, batch)

    def get_address(self, address: bytes) -> AddressState:
        # FIXME: Avoid two calls to know if address is not recognized (merged with is used)
        try:
            return self._get_address_state(address)
        except KeyError:
            # FIXME: Check all cases where address is not found
            return AddressState.create(address=address,
                                       nonce=config.dev.default_nonce,
                                       balance=config.dev.default_account_balance,
                                       pubhashes=[],
                                       tokens=dict())

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

    def get_batch(self):
        return self._db.get_batch()

    def write_batch(self, batch):
        self._db.write_batch(batch)

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
