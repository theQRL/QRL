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
from qrl.core.Transaction import Transaction, TokenTransaction, TransferTokenTransaction, CoinBase
from qrl.core.TokenMetadata import TokenMetadata
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.EphemeralMetadata import EphemeralMetadata
from qrl.core.AddressState import AddressState
from qrl.generated import qrl_pb2


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

    def get_block_size_limit(self, block: Block):
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
        self._db.put_raw(bin2hstr(block.headerhash).encode(), block.to_json().encode(), batch)

    def get_block(self, header_hash: bytes) -> Optional[Block]:
        try:
            json_data = self._db.get_raw(bin2hstr(header_hash).encode())
            return Block.from_json(json_data)
        except KeyError:
            logger.debug('[get_block] Block header_hash %s not found', bin2hstr(header_hash).encode())
        except Exception as e:
            logger.error('[get_block] %s', e)

        return None

    def put_block_metadata(self, headerhash: bytes, block_metadata: BlockMetadata, batch):
        self._db.put_raw(b'metadata_' + bin2hstr(headerhash).encode(), block_metadata.to_json(), batch)

    def get_block_metadata(self, header_hash: bytes) -> Optional[BlockMetadata]:
        try:
            json_data = self._db.get_raw(b'metadata_' + bin2hstr(header_hash).encode())
            return BlockMetadata.from_json(json_data)
        except KeyError:
            logger.debug('[get_block_metadata] Block header_hash %s not found',
                         b'metadata_' + bin2hstr(header_hash).encode())
        except Exception as e:
            logger.error('[get_block_metadata] %s', e)

        return None

    def remove_blocknumber_mapping(self, block_number, batch):
        self._db.delete(str(block_number).encode(), batch)

    def put_block_number_mapping(self, block_number: int, block_number_mapping, batch):
        self._db.put_raw(str(block_number).encode(), MessageToJson(block_number_mapping).encode(), batch)

    def get_block_number_mapping(self, block_number: int) -> Optional[qrl_pb2.BlockNumberMapping]:
        try:
            json_data = self._db.get_raw(str(block_number).encode())
            block_number_mapping = qrl_pb2.BlockNumberMapping()
            return Parse(json_data, block_number_mapping)
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

    def get_state(self, header_hash: bytes, addresses_set: set):
        tmp_header_hash = header_hash

        hash_path = []
        while True:
            block = self.get_block(header_hash)
            if not block:
                raise Exception('[get_state] No Block Found %s, Initiator %s', header_hash, tmp_header_hash)
            mainchain_block = self.get_block_by_number(block.block_number)
            if mainchain_block and mainchain_block.headerhash == block.headerhash:
                break
            if block.block_number == 0:
                raise Exception('[get_state] Alternate chain genesis is different, Initiator %s', tmp_header_hash)
            hash_path.append(header_hash)
            header_hash = block.prev_headerhash

        rollback_headerhash = header_hash

        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self.get_address_state(address)

        block = self.last_block
        while block.headerhash != rollback_headerhash:
            # Deplay transactions in reverse order, otherwise could result into negative value
            for tx_protobuf in block.transactions[-1::-1]:
                tx = Transaction.from_pbdata(tx_protobuf)
                tx.revert_state_changes(addresses_state, self)
            block = self.get_block(block.prev_headerhash)

        for header_hash in hash_path[-1::-1]:
            block = self.get_block(header_hash)

            for tx_pbdata in block.transactions:
                tx = Transaction.from_pbdata(tx_pbdata)
                tx.apply_state_changes(addresses_state)

        return addresses_state, rollback_headerhash, hash_path

    def get_ephemeral_metadata(self, msg_id: bytes):
        try:
            json_ephemeral_metadata = self._db.get_raw(b'ephemeral_' + msg_id)

            return EphemeralMetadata.from_json(json_ephemeral_metadata)
        except KeyError:
            pass
        except Exception as e:
            logger.exception(e)

        return EphemeralMetadata()

    def update_ephemeral(self, encrypted_ephemeral: EncryptedEphemeralMessage):
        ephemeral_metadata = self.get_ephemeral_metadata(encrypted_ephemeral.msg_id)
        ephemeral_metadata.add(encrypted_ephemeral)

        self._db.put_raw(b'ephemeral_' + encrypted_ephemeral.msg_id, ephemeral_metadata.to_json().encode())

    def get_mainchain_height(self) -> int:
        try:
            return self._db.get('blockheight')
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
        self._db.put('blockheight', height, batch)

    def remove_last_tx(self, block, batch):
        if len(block.transactions) == 0:
            return

        try:
            last_txn = self._db.get(b'last_txn')
        except:  # noqa
            return

        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            i = 0
            while i < len(last_txn):
                tx = Transaction.from_json(last_txn[i][0])
                if txn.txhash == tx.txhash:
                    del last_txn[i]
                    break
                i += 1

        self._db.put(b'last_txn', last_txn, batch)

    def update_last_tx(self, block, batch):
        if len(block.transactions) == 0:
            return
        last_txn = []

        try:
            last_txn = self._db.get(b'last_txn')
        except:  # noqa
            pass

        for protobuf_txn in block.transactions[-20:]:
            txn = Transaction.from_pbdata(protobuf_txn)
            if isinstance(txn, CoinBase):
                continue
            last_txn.insert(0, [txn.to_json(),
                                block.block_number,
                                block.timestamp])

        del last_txn[20:]
        self._db.put(b'last_txn', last_txn, batch)

    def get_last_txs(self):
        try:
            last_txn = self._db.get(b'last_txn')
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

    def get_token_metadata(self, token_txhash: bytes):
        try:
            json_data = self._db.get_raw(b'token_' + token_txhash)
            return TokenMetadata.from_json(json_data)
        except KeyError:
            pass
        except Exception as e:
            logger.error('[get_token_metadata] %s', e)

        return None

    def update_token_metadata(self, transfer_token: TransferTokenTransaction):
        token_metadata = self.get_token_metadata(transfer_token.token_txhash)
        token_metadata.update([transfer_token.txhash])
        self._db.put_raw(b'token_' + transfer_token.token_txhash,
                         token_metadata.to_json().encode())

    def create_token_metadata(self, token: TokenTransaction):
        token_metadata = TokenMetadata.create(token_txhash=token.txhash, transfer_token_txhashes=[token.txhash])
        self._db.put_raw(b'token_' + token.txhash,
                         token_metadata.to_json().encode())

    def remove_transfer_token_metadata(self, transfer_token: TransferTokenTransaction):
        token_metadata = self.get_token_metadata(transfer_token.token_txhash)
        token_metadata.remove(transfer_token.txhash)
        self._db.put_raw(b'token_' + transfer_token.token_txhash,
                         token_metadata.to_json().encode())

    def remove_token_metadata(self, token: TokenTransaction):
        self._db.delete(b'token_' + token.txhash)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def get_txn_count(self, addr):
        try:
            return self._db.get(b'txn_count_' + addr)
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
            fee_reward -= txn.fee
            self.remove_tx_metadata(txn, batch)
            # FIXME: Being updated without batch, need to fix,
            if isinstance(txn, TransferTokenTransaction):
                self.remove_transfer_token_metadata(txn)
            elif isinstance(txn, TokenTransaction):
                self.remove_token_metadata(txn)
            self.decrease_txn_count(self.get_txn_count(txn.addr_from),
                                    txn.addr_from)

        txn = Transaction.from_pbdata(block.transactions[0])  # Coinbase Transaction
        self.update_total_coin_supply(fee_reward - txn.amount)
        self.remove_last_tx(block, batch)

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
            self.increase_txn_count(self.get_txn_count(txn.addr_from),
                                    txn.addr_from)

        txn = Transaction.from_pbdata(block.transactions[0])  # Coinbase Transaction
        self.update_total_coin_supply(txn.amount - fee_reward)
        self.update_last_tx(block, batch)

    def remove_tx_metadata(self, txn, batch):
        try:
            self._db.delete(bin2hstr(txn.txhash).encode(), batch)
        except Exception:
            pass

    def put_tx_metadata(self, txn, block_number, timestamp, batch):
        try:
            self._db.put(bin2hstr(txn.txhash),
                         [txn.to_json(), block_number, timestamp],
                         batch)
        except Exception:
            pass

    def get_tx_metadata(self, txhash: bytes):
        try:
            tx_metadata = self._db.get(bin2hstr(txhash))
        except Exception:
            return None
        if tx_metadata is None:
            return None
        txn_json, block_number, _ = tx_metadata
        return Transaction.from_json(txn_json), block_number

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def increase_txn_count(self, last_count: int, addr: bytes):
        # FIXME: This should be transactional
        self._db.put(b'txn_count_' + addr, last_count + 1)

    def decrease_txn_count(self, last_count: int, addr: bytes):
        # FIXME: This should be transactional
        if last_count == 0:
            raise ValueError('Cannot decrease transaction count last_count: %s, addr %s',
                             last_count, bin2hstr(addr))
        self._db.put(b'txn_count_' + addr, last_count - 1)

    def get_address_state(self, address: bytes) -> AddressState:
        try:
            data = self._db.get_raw(address)
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            return address_state
        except KeyError:
            return AddressState.get_default(address)

    def nonce(self, addr: bytes) -> int:
        return self.get_address_state(addr).nonce

    def balance(self, addr: bytes) -> int:
        return self.get_address_state(addr).balance

    def address_used(self, address: bytes):
        # FIXME: Probably obsolete
        try:
            return self.get_address_state(address)
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

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def update_total_coin_supply(self, balance):
        self._db.put(b'total_coin_supply', self.total_coin_supply() + balance)

    def total_coin_supply(self):
        try:
            return self._db.get(b'total_coin_supply')
        except KeyError:
            return 0

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

    def delete(self, key, batch):
        self._db.delete(key, batch)

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
