# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional
from statistics import median

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.cache.LRU import LRUStateCache
from qrl.core.BlockMetadata import BlockMetadata
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.Block import Block
from qrl.core.misc import logger, db
from qrl.core.Transaction import Transaction, TokenTransaction, TransferTokenTransaction
from qrl.core.TokenMetadata import TokenMetadata
from qrl.core.TokenList import TokenList
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.EphemeralMetadata import EphemeralMetadata
from qrl.core.AddressState import AddressState
from qrl.generated import qrl_pb2


class StateLoader:

    def __init__(self, state_code, db: db.DB):
        self._db = db
        self.state_code = state_code
        if state_code != b'current_':
            json_data = self._db.get_raw(self.state_code)
            self._block_number = Block.from_json(json_data).block_number
        self._data = qrl_pb2.StateLoader()
        try:
            json_data = self._db.get_raw(b'state' + self.state_code)
            if json_data:
                Parse(json_data, self._data)
        except KeyError:
            pass

    @property
    def block_number(self):
        return self._block_number

    def get_address(self, address: bytes) -> Optional[AddressState]:
        modified_address = self.state_code + address
        try:
            data = self._db.get_raw(modified_address)
            if data is None:
                raise KeyError("{} not found modified address".format(modified_address))
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            return address_state
        except KeyError:
            return None

    def add_address(self, address):
        if address not in self._data.addresses:
            self._data.addresses.append(address)

    def put_addresses_state(self, addresses_state: dict, batch=None):
        for address in addresses_state:
            address_state = addresses_state[address]
            data = address_state.pbdata.SerializeToString()
            self._db.put_raw(self.state_code + address_state.address, data, batch)
            self.add_address(address)

        self._db.put_raw(b'state' + self.state_code, MessageToJson(self._data).encode(), batch)

    def destroy(self, batch=None):
        for address in self._data.addresses:
            self._db.delete(self.state_code + address, batch)
        del self._data.addresses[:]

    def update_main(self, batch=None):
        for address in self._data.addresses:
            address_state = self._db.get_raw(self.state_code + address)
            self._db.put_raw(address, address_state, batch)
        self.destroy(batch)

    def commit(self, state_loader, batch=None):
        # TODO (cyyber): Optimization, instead of moving from current to headerhash,
        # blocknumber could be used in state_code, and current could point to cache of
        # latest blocknumber
        for address in self._data.addresses:
            data = self._db.get_raw(self.state_code + address)
            if data is None:
                logger.warning('>>>>>>>>> GOT NONE <<<<<<< %s', address)
            self._db.put_raw(state_loader.state_code + address, data, batch)
            state_loader.add_address(address)
            self._db.delete(self.state_code + address, batch)
        del self._data.addresses[:]
        self._db.put_raw(b'state' + self.state_code, MessageToJson(self._data).encode(), batch)


class StateObjects:

    def __init__(self, db):
        self._db = db
        self._state_loaders = []
        self._current_state = StateLoader(state_code=b'current_',
                                          db=db)
        self._data = qrl_pb2.StateObjects()
        try:
            json_data = self._db.get_raw(b'state_objects')
            Parse(json_data, self._data)
            for state_code in self._data.state_loaders:
                state_loader = StateLoader(state_code=state_code,
                                           db=db)
                self._state_loaders.append(state_loader)
        except KeyError:
            pass

    @property
    def state_loaders(self):
        return self._state_loaders

    def get_address(self, address):
        address_state = self._current_state.get_address(address)
        if address_state:
            return address_state

        for state_loader in self._state_loaders[-1::-1]:
            address_state = state_loader.get_address(address)
            if address_state:
                return address_state
        return None

    def get(self, state_code):
        for state_obj in self._state_loaders:
            if state_obj.state_code == state_code:
                return state_obj
        return None

    def push(self, headerhash: bytes, batch=None):
        state_loader = StateLoader(state_code=bin2hstr(headerhash).encode(), db=self._db)
        self._current_state.commit(state_loader)

        self._data.state_loaders.append(state_loader.state_code)
        self._state_loaders.append(state_loader)

        if len(self._state_loaders) > config.user.max_state_limit:
            state_loader = self._state_loaders[0]
            del self._state_loaders[0]
            del self._data.state_loaders[0]
            state_loader.update_main()

        self._db.put_raw(b'state_objects', MessageToJson(self._data).encode(), batch)

    def update_current_state(self, addresses_state: dict):
        self._current_state.put_addresses_state(addresses_state)

    def contains(self, headerhash: bytes) -> bool:
        str_headerhash = bin2hstr(headerhash).encode()
        for state_obj in self._state_loaders:
            if state_obj.state_code == str_headerhash:
                return True
        return False

    def get_state_loader_by_index(self, index) -> StateLoader:
        if index >= len(self._state_loaders):
            logger.warning('Index is not in range')
            logger.warning('Index: %s, Len of State_loaders: %s', index, len(self._state_loaders))
            raise Exception

        return self._state_loaders[index]

    def destroy_state_loader(self, index):
        self._state_loaders[index].destroy()
        del self._state_loaders[index]

    def destroy_fork_states(self, block_number, headerhash):
        """
        Removes all the cache state, which are created further,
        the current blocknumber.
        Usually done when a new branch found as main branch.
        :param block_number:
        :param headerhash:
        :return:
        """
        str_headerhash = bin2hstr(headerhash).encode()
        len_state_loaders = len(self._state_loaders)
        index = 0
        while index < len_state_loaders:
            state_loader = self._state_loaders[index]
            logger.debug('Comparing #%s>%s', state_loader.block_number, block_number)
            if state_loader.block_number > block_number:
                logger.debug('Destroyed State #%s', state_loader.block_number)
                self.destroy_state_loader(index)
                len_state_loaders -= 1
                continue

            if state_loader.block_number == block_number:
                if state_loader.state_code != str_headerhash:
                    self.destroy_state_loader(index)
                    len_state_loaders -= 1
                    continue

            index += 1

    def destroy_current_state(self, batch):
        self._current_state.destroy(batch)


class State:
    # FIXME: Rename to PersistentState
    # FIXME: Move blockchain caching/storage over here
    # FIXME: Improve key generation

    def __init__(self):
        self._db = db.DB()  # generate db object here
        self.state_cache = LRUStateCache(config.user.lru_state_cache_size, self._db)
        self.state_objects = StateObjects(self._db)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._db is not None:
            if self._db.db is not None:
                del self._db.db
            del self._db
            self._db = None

    def get_block_size_limit(self, block):
        block_size_list = []
        for _ in range(0, 10):
            block = self.get_block(block.prev_headerhash)
            if not block:
                return None
            block_size_list.append(block.size)
            if block.block_number == 0:
                break
        return max(config.dev.block_min_size_limit, config.dev.size_multiplier * median(block_size_list))

    def put_block(self, block, batch):
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

    def put_block_metadata(self, headerhash, block_metadata, batch):
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

    def put_block_number_mapping(self, block_number, block_number_mapping, batch):
        self._db.put_raw(str(block_number).encode(), MessageToJson(block_number_mapping).encode(), batch)

    def get_block_number_mapping(self, block_number: bytes) -> Optional[qrl_pb2.BlockNumberMapping]:
        try:
            json_data = self._db.get_raw(str(block_number).encode())
            block_number_mapping = qrl_pb2.BlockNumberMapping()
            return Parse(json_data, block_number_mapping)
        except KeyError:
            logger.debug('[get_block_number_mapping] Block #%s not found', block_number)
        except Exception as e:
            logger.error('[get_block_number_mapping] %s', e)

        return None

    def get_block_by_number(self, block_number) -> Optional[Block]:
        block_number_mapping = self.get_block_number_mapping(block_number)
        if not block_number_mapping:
            return None
        return self.get_block(block_number_mapping.headerhash)

    @staticmethod
    def prepare_address_list(block) -> set:
        addresses = set()
        for proto_tx in block.transactions:
            tx = Transaction.from_pbdata(proto_tx)
            tx.set_effected_address(addresses)

        for genesis_balance in GenesisBlock().genesis_balance:
            bytes_addr = genesis_balance.address.encode()
            if bytes_addr not in addresses:
                addresses.add(bytes_addr)

        return addresses

    def set_addresses_state(self, addresses_state: dict, state_code: bytes):
        """
        Sets the addresses_state from the latest state objects cache from or after
        state_code.
        :param addresses_state:
        :param state_code:
        :return:
        """
        str_state_code = bin2hstr(state_code).encode()
        index = -1
        found = False
        for state_object in self.state_objects.state_loaders:
            index += 1
            if state_object.state_code == str_state_code:
                found = True
                break

        if not found:
            logger.warning('Not Possible: State Code not found %s', str_state_code)
            raise Exception

        for address in addresses_state:
            for state_obj_index in range(index, -1, -1):
                state_object = self.state_objects.get_state_loader_by_index(state_obj_index)
                addresses_state[address] = state_object.get_address(address)
                if addresses_state[address]:
                    break
            if not addresses_state[address]:
                addresses_state[address] = self._get_address_state(address)

    def get_state_mainchain(self, addresses_set):
        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self.get_address(address)
        return addresses_state

    def get_state(self, header_hash, addresses_set):
        tmp_header_hash = header_hash
        parent_headerhash = None

        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = None

        while True:
            if self.state_objects.contains(header_hash):
                parent_headerhash = header_hash
                self.set_addresses_state(addresses_state, header_hash)
                break
            block = self.get_block(header_hash)
            if not block:
                logger.warning('[get_state] No Block Found %s', header_hash)
                break
            if block.block_number == 0:
                break
            header_hash = block.prev_headerhash

        for genesis_balance in GenesisBlock().genesis_balance:
            bytes_addr = genesis_balance.address.encode()
            if not addresses_state[bytes_addr]:
                addresses_state[bytes_addr] = AddressState.get_default(bytes_addr)
                addresses_state[bytes_addr]._data.balance = genesis_balance.balance

        for address in addresses_state:
            if not addresses_state[address]:
                addresses_state[address] = AddressState.get_default(address)

        header_hash = tmp_header_hash
        hash_path = []
        while True:
            if parent_headerhash == header_hash:
                break
            block = self.get_block(header_hash)
            if not block:
                break
            hash_path.append(header_hash)
            header_hash = block.prev_headerhash
            if block.block_number == 0:
                break

        for header_hash in hash_path[-1::-1]:
            block = self.get_block(header_hash)

            for tx_pbdata in block.transactions:
                tx = Transaction.from_pbdata(tx_pbdata)
                tx.apply_on_state(addresses_state)

        return addresses_state

    def update_state(self, addresses_state):
        for address in addresses_state:
            self._save_address_state(addresses_state[address])

    def update_mainchain_state(self, addresses_state, block_number, headerhash):
        if block_number % config.dev.cache_frequency == 0:
            self.state_cache.set(headerhash, addresses_state)

        self.state_objects.destroy_fork_states(block_number, headerhash)
        self.state_objects.update_current_state(addresses_state)

        if block_number % config.dev.cache_frequency == 0:
            self.state_objects.push(headerhash)

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

    def update_mainchain_height(self, height, batch):
        self._db.put('blockheight', height, batch)

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
            if txn.subtype == qrl_pb2.Transaction.COINBASE:
                continue
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
        json_data = self._db.get_raw(b'token_' + token_txhash)
        return TokenMetadata.from_json(json_data)

    def update_token_metadata(self, transfer_token: TransferTokenTransaction):
        token_metadata = self.get_token_metadata(transfer_token.token_txhash)
        token_metadata.update([transfer_token.txhash])
        self._db.put_raw(b'token_' + transfer_token.token_txhash,
                         token_metadata.to_json().encode())

    def create_token_metadata(self, token: TokenTransaction):
        token_metadata = TokenMetadata.create(token_txhash=token.txhash, transfer_token_txhashes=[token.txhash])
        self._db.put_raw(b'token_' + token.txhash,
                         token_metadata.to_json().encode())

    def get_state_version(self):
        return self._db.get(b'state_version')

    def update_state_version(self, block_number, batch):
        self._db.put(b'state_version', block_number, batch)

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

        # TODO (cyyber): Move To State Cache, instead of writing directly
        for protobuf_txn in block.transactions:
            txn = Transaction.from_pbdata(protobuf_txn)
            self._db.put(bin2hstr(txn.txhash),
                         [txn.to_json(), block.block_number, block.timestamp],
                         batch)
            # FIXME: Being updated without batch, need to fix,
            if txn.subtype == qrl_pb2.Transaction.TRANSFERTOKEN:
                self.update_token_metadata(txn)
            if txn.subtype == qrl_pb2.Transaction.TOKEN:
                self.create_token_metadata(txn)

            self.increase_txn_count(txn.txfrom)

        self.update_last_tx(block, batch)
        # Disabled as complete token list over the network is not required
        # if token_list:
        #    self.update_token_list(token_list, batch)

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

    def _get_address_state(self, address: bytes) -> AddressState:
        try:
            data = self._db.get_raw(address)
            pbdata = qrl_pb2.AddressState()
            pbdata.ParseFromString(bytes(data))
            address_state = AddressState(pbdata)
            return address_state
        except KeyError:
            return AddressState.get_default(address)

    def _save_address_state(self, address_state: AddressState, batch=None):
        data = address_state.pbdata.SerializeToString()
        self._db.put_raw(address_state.address, data, batch)

    def get_address(self, address: bytes) -> AddressState:
        address_state = self.state_objects.get_address(address)

        if not address_state:
            return self._get_address_state(address)

        return address_state

    def nonce(self, addr: bytes) -> int:
        return self.get_address(addr).nonce

    def balance(self, addr: bytes) -> int:
        return self.get_address(addr).balance

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
