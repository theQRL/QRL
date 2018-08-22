# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional
from statistics import median

import functools
from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import UInt256ToString

from qrl.core import config
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Block import Block
from qrl.core.misc import logger, db
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.txs.TokenTransaction import TokenTransaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.TokenMetadata import TokenMetadata
from qrl.core.AddressState import AddressState
from qrl.core.LastTransactions import LastTransactions
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.generated import qrl_pb2, qrlstateinfo_pb2


class State:
    # FIXME: Rename to PersistentState
    # FIXME: Move blockchain caching/storage over here
    # FIXME: Improve key generation

    def __init__(self):
        self._db = db.DB()  # generate db object here

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._db is not None:
            if self._db.db is not None:
                del self._db.db
            del self._db
            self._db = None

    @property
    def batch(self):
        return self._db.get_batch()

    @property
    def total_coin_supply(self):
        try:
            return int.from_bytes(self._db.get_raw(b'total_coin_supply'), byteorder='big', signed=False)
        except KeyError:
            return 0

    def get_block_size_limit(self, block: Block):
        # NOTE: Miner /
        block_size_list = []
        for _ in range(0, 10):
            block = self.get_block(block.prev_headerhash)
            if not block:
                return None
            block_size_list.append(block.size)
            if block.block_number == 0:
                break
        return max(config.dev.block_min_size_limit, config.dev.size_multiplier * median(block_size_list))

    def put_block(self, block: Block, batch):
        self._db.put_raw(block.headerhash, block.serialize(), batch)

    def get_block(self, header_hash: bytes) -> Optional[Block]:
        try:
            data = self._db.get_raw(header_hash)
            return Block.deserialize(data)
        except KeyError:
            logger.debug('[get_block] Block header_hash %s not found', bin2hstr(header_hash).encode())
        except Exception as e:
            logger.error('[get_block] %s', e)

        return None

    def put_block_metadata(self, headerhash: bytes, block_metadata: BlockMetadata, batch):
        self._db.put_raw(b'metadata_' + headerhash, block_metadata.serialize(), batch)

    def get_block_metadata(self, header_hash: bytes) -> Optional[BlockMetadata]:
        try:
            data = self._db.get_raw(b'metadata_' + header_hash)
            return BlockMetadata.deserialize(data)
        except KeyError:
            logger.debug('[get_block_metadata] Block header_hash %s not found',
                         b'metadata_' + bin2hstr(header_hash).encode())
        except Exception as e:
            logger.error('[get_block_metadata] %s', e)

        return None

    def remove_blocknumber_mapping(self, block_number, batch):
        self._db.delete(str(block_number).encode(), batch)

    def put_block_number_mapping(self, block_number: int, block_number_mapping, batch):
        self._db.put_raw(str(block_number).encode(), MessageToJson(block_number_mapping, sort_keys=True).encode(), batch)

    def get_block_number_mapping(self, block_number: int) -> Optional[qrl_pb2.BlockNumberMapping]:
        try:
            data = self._db.get_raw(str(block_number).encode())
            block_number_mapping = qrl_pb2.BlockNumberMapping()
            return Parse(data, block_number_mapping)
        except KeyError:
            logger.debug('[get_block_number_mapping] Block #%s not found', block_number)
        except Exception as e:
            logger.error('[get_block_number_mapping] %s', e)

        return None

    def get_block_by_number(self, block_number: int) -> Optional[Block]:
        block_number_mapping = self.get_block_number_mapping(block_number)
        if not block_number_mapping:
            return None
        return self.get_block(block_number_mapping.headerhash)

    def get_block_header_hash_by_number(self, block_number: int):
        block_number_mapping = self.get_block_number_mapping(block_number)
        if not block_number_mapping:
            return None
        return block_number_mapping.headerhash

    @staticmethod
    def prepare_address_list(block) -> set:
        addresses = set()
        for proto_tx in block.transactions:
            tx = Transaction.from_pbdata(proto_tx)
            tx.set_affected_address(addresses)

        for genesis_balance in GenesisBlock().genesis_balance:
            bytes_addr = genesis_balance.address
            if bytes_addr not in addresses:
                addresses.add(bytes_addr)

        return addresses

    def put_addresses_state(self, addresses_state: dict, batch=None):
        """
        :param addresses_state:
        :param batch:
        :return:
        """
        for address in addresses_state:
            address_state = addresses_state[address]
            data = address_state.pbdata.SerializeToString()
            self._db.put_raw(address_state.address, data, batch)

    def get_state_mainchain(self, addresses_set: set):
        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self.get_address_state(address)
        return addresses_state

    def get_mainchain_height(self) -> int:
        try:
            return int.from_bytes(self._db.get_raw(b'blockheight'), byteorder='big', signed=False)
        except KeyError:
            pass
        except Exception as e:
            logger.error('get_blockheight Exception %s', e)

        return -1

    @property
    def last_block(self):
        block_number = self.get_mainchain_height()
        return self.get_block_by_number(block_number)

    def update_mainchain_height(self, height, batch):
        self._db.put_raw(b'blockheight', height.to_bytes(8, byteorder='big', signed=False), batch)

    def _remove_last_tx(self, block, batch):
        if len(block.transactions) == 0:
            return

        try:
            last_txn = LastTransactions.deserialize(self._db.get_raw(b'last_txn'))
        except:  # noqa
            return

        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            i = 0
            while i < len(last_txn.tx_metadata):
                tx = Transaction.from_pbdata(last_txn.tx_metadata[i].transaction)
                if txn.txhash == tx.txhash:
                    del last_txn.tx_metadata[i]
                    break
                i += 1

        self._db.put_raw(b'last_txn', last_txn.serialize(), batch)

    def _update_last_tx(self, block, batch):
        if len(block.transactions) == 0:
            return
        last_txn = LastTransactions()

        try:
            last_txn = LastTransactions.deserialize(self._db.get_raw(b'last_txn'))
        except:  # noqa
            pass

        for protobuf_txn in block.transactions[-20:]:
            txn = Transaction.from_pbdata(protobuf_txn)
            if isinstance(txn, CoinBase):
                continue
            last_txn.add(txn, block.block_number, block.timestamp)

        self._db.put_raw(b'last_txn', last_txn.serialize(), batch)

    def get_last_txs(self):
        try:
            last_txn = LastTransactions.deserialize(self._db.get_raw(b'last_txn'))
        except:  # noqa
            return []

        txs = []
        for tx_metadata in last_txn.tx_metadata:
            data = tx_metadata.transaction
            tx = Transaction.from_pbdata(data)
            txs.append(tx)

        return txs

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def get_token_metadata(self, token_txhash: bytes):
        try:
            data = self._db.get_raw(b'token_' + token_txhash)
            return TokenMetadata.deserialize(data)
        except KeyError:
            pass
        except Exception as e:
            logger.error('[get_token_metadata] %s', e)

        return None

    def update_token_metadata(self, transfer_token: TransferTokenTransaction):
        token_metadata = self.get_token_metadata(transfer_token.token_txhash)
        token_metadata.update([transfer_token.txhash])
        self._db.put_raw(b'token_' + transfer_token.token_txhash,
                         token_metadata.serialize())

    def create_token_metadata(self, token: TokenTransaction):
        token_metadata = TokenMetadata.create(token_txhash=token.txhash, transfer_token_txhashes=[token.txhash])
        self._db.put_raw(b'token_' + token.txhash,
                         token_metadata.serialize())

    def remove_transfer_token_metadata(self, transfer_token: TransferTokenTransaction):
        token_metadata = self.get_token_metadata(transfer_token.token_txhash)
        token_metadata.remove(transfer_token.txhash)
        self._db.put_raw(b'token_' + transfer_token.token_txhash,
                         token_metadata.serialize())

    def remove_token_metadata(self, token: TokenTransaction):
        self._db.delete(b'token_' + token.txhash)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def get_txn_count(self, addr):
        try:
            return int.from_bytes(self._db.get_raw(b'txn_count_' + addr), byteorder='big', signed=False)
        except KeyError:
            pass
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in get_txn_count')
            logger.exception(e)

        return 0

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def rollback_tx_metadata(self, block, batch):
        fee_reward = 0
        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            fee_reward += txn.fee
            self.remove_tx_metadata(txn, batch)
            # FIXME: Being updated without batch, need to fix,
            if isinstance(txn, TransferTokenTransaction):
                self.remove_transfer_token_metadata(txn)
            elif isinstance(txn, TokenTransaction):
                self.remove_token_metadata(txn)
            self._decrease_txn_count(self.get_txn_count(txn.addr_from),
                                     txn.addr_from)

        txn = Transaction.from_pbdata(block.transactions[0])  # Coinbase Transaction
        self._update_total_coin_supply(fee_reward - txn.amount)
        self._remove_last_tx(block, batch)

    def update_tx_metadata(self, block, batch):
        fee_reward = 0
        # TODO (cyyber): Move To State Cache, instead of writing directly
        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            fee_reward += txn.fee
            self.put_tx_metadata(txn,
                                 block.block_number,
                                 block.timestamp,
                                 batch)
            # FIXME: Being updated without batch, need to fix,
            if isinstance(txn, TransferTokenTransaction):
                self.update_token_metadata(txn)
            elif isinstance(txn, TokenTransaction):
                self.create_token_metadata(txn)
            self._increase_txn_count(self.get_txn_count(txn.addr_from),
                                     txn.addr_from)

        txn = Transaction.from_pbdata(block.transactions[0])  # Coinbase Transaction
        self._update_total_coin_supply(txn.amount - fee_reward)
        self._update_last_tx(block, batch)

    def remove_tx_metadata(self, txn, batch):
        try:
            self._db.delete(txn.txhash, batch)
        except Exception:
            pass

    def put_tx_metadata(self, txn: Transaction, block_number: int, timestamp: int, batch):
        try:
            tm = TransactionMetadata.create(tx=txn,
                                            block_number=block_number,
                                            timestamp=timestamp)
            self._db.put_raw(txn.txhash,
                             tm.serialize(),
                             batch)
        except Exception:
            pass

    def get_tx_metadata(self, txhash: bytes):
        try:
            tx_metadata = TransactionMetadata.deserialize(self._db.get_raw(txhash))
        except Exception:
            return None

        data, block_number = tx_metadata.transaction, tx_metadata.block_number
        return Transaction.from_pbdata(data), block_number

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def _increase_txn_count(self, last_count: int, addr: bytes):
        # FIXME: This should be transactional
        self._db.put_raw(b'txn_count_' + addr, (last_count + 1).to_bytes(8, byteorder='big', signed=False))

    def _decrease_txn_count(self, last_count: int, addr: bytes):
        # FIXME: This should be transactional
        if last_count == 0:
            raise ValueError('Cannot decrease transaction count last_count: %s, addr %s',
                             last_count, bin2hstr(addr))
        self._db.put_raw(b'txn_count_' + addr, (last_count - 1).to_bytes(8, byteorder='big', signed=False))

    def get_address_state(self, address: bytes) -> AddressState:
        try:
            data = self._db.get_raw(address)
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            return address_state
        except KeyError:
            return AddressState.get_default(address)

    def get_all_address_state(self) -> list:
        addresses_state = []

        try:
            for address in self._db.get_db_keys(False):
                if AddressState.address_is_valid(address) or address == config.dev.coinbase_address:
                    addresses_state.append(self.get_address_state(address).pbdata)
            return addresses_state
        except Exception as e:
            logger.error("Exception in get_addresses_state %s", e)

        return []

    def get_address_balance(self, addr: bytes) -> int:
        return self.get_address_state(addr).balance

    def get_address_nonce(self, addr: bytes) -> int:
        return self.get_address_state(addr).nonce

    def get_address_is_used(self, address: bytes) -> bool:
        # FIXME: Probably obsolete
        try:
            return self.get_address_state(address) is not None
        except KeyError:
            return False
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in address_used')
            logger.exception(e)
            raise

    def _return_all_addresses(self):
        addresses = []
        for key, data in self._db.RangeIter(b'Q', b'Qz'):
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            addresses.append(address_state)
        return addresses

    def write_batch(self, batch):
        self._db.write_batch(batch)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def _update_total_coin_supply(self, balance):
        self._db.put_raw(b'total_coin_supply', (self.total_coin_supply + balance).to_bytes(8, byteorder='big', signed=False))

    def get_measurement(self, block_timestamp, parent_headerhash, parent_metadata: BlockMetadata):
        count_headerhashes = len(parent_metadata.last_N_headerhashes)

        if count_headerhashes == 0:
            return config.dev.mining_setpoint_blocktime
        elif count_headerhashes == 1:
            nth_block = self.get_block(parent_headerhash)
            count_headerhashes += 1
        else:
            nth_block = self.get_block(parent_metadata.last_N_headerhashes[1])

        nth_block_timestamp = nth_block.timestamp
        if count_headerhashes < config.dev.N_measurement:
            nth_block_timestamp -= config.dev.mining_setpoint_blocktime

        return (block_timestamp - nth_block_timestamp) // count_headerhashes

    def _delete(self, key, batch):
        self._db.delete(key, batch)

    def put_fork_state(self, fork_state: qrlstateinfo_pb2.ForkState, batch=None):
        self._db.put_raw(b'fork_state', fork_state.SerializeToString(), batch)

    def get_fork_state(self) -> Optional[qrlstateinfo_pb2.ForkState]:
        try:
            data = self._db.get_raw(b'fork_state')
            fork_state = qrlstateinfo_pb2.ForkState()
            fork_state.ParseFromString(bytes(data))
            return fork_state
        except KeyError:
            return None
        except Exception as e:
            logger.error('Exception in get_fork_state')
            logger.exception(e)
            raise

    def delete_fork_state(self, batch=None):
        self._db.delete(b'fork_state', batch)

    @functools.lru_cache(maxsize=config.dev.block_timeseries_size + 50)
    def get_block_datapoint(self, headerhash):
        block = self.get_block(headerhash)
        if block is None:
            return None

        block_metadata = self.get_block_metadata(headerhash)
        prev_block_metadata = self.get_block_metadata(block.prev_headerhash)
        prev_block = self.get_block(block.prev_headerhash)

        data_point = qrl_pb2.BlockDataPoint()
        data_point.number = block.block_number
        data_point.header_hash = headerhash
        if prev_block is not None:
            data_point.header_hash_prev = prev_block.headerhash
        data_point.timestamp = block.timestamp
        data_point.time_last = 0
        data_point.time_movavg = 0
        data_point.difficulty = UInt256ToString(block_metadata.block_difficulty)

        if prev_block is not None:
            data_point.time_last = block.timestamp - prev_block.timestamp
            if prev_block.block_number == 0:
                data_point.time_last = config.dev.mining_setpoint_blocktime

            movavg = self.get_measurement(block.timestamp,
                                          block.prev_headerhash,
                                          prev_block_metadata)
            data_point.time_movavg = movavg

            try:
                # FIXME: need to consider average difficulty here
                data_point.hash_power = int(data_point.difficulty) * (config.dev.mining_setpoint_blocktime / movavg)
            except ZeroDivisionError:
                data_point.hash_power = 0

        return data_point
