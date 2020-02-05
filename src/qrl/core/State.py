# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from typing import Optional

from qrl.core import config
from qrl.core.misc import logger, db
from qrl.generated import qrl_pb2, qrlstateinfo_pb2


class State:
    # FIXME: Rename to PersistentState
    # FIXME: Move blockchain caching/storage over here
    # FIXME: Improve key generation

    def __init__(self, my_db=None):
        self._db = my_db
        if not my_db:
            self._db = db.DB()  # generate db object here
        self._tmp_state = None  # Temporary State file which needs to be fetched during migration to new db
        self._state_version = 1  # Change State Version, each time any change made to leveldb structure

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._db is not None:
            if self._db.db is not None:
                del self._db.db
            del self._db
            self._db = None

    @property
    def state_version(self):
        return self._state_version

    @property
    def batch(self):
        return self._db.get_batch()

    @property
    def total_coin_supply(self):
        try:
            return int.from_bytes(self._db.get_raw(b'total_coin_supply'), byteorder='big', signed=False)
        except KeyError:
            return 0

    def get_state_version(self) -> int:
        try:
            version = self._db.get_raw(b'state_version')
            return int(version.decode())
        except KeyError:
            return 0
        except Exception:
            raise Exception("Exception while retrieving version")

    def put_state_version(self):
        try:
            self._db.put_raw(b'state_version', str(self._state_version).encode())
        except Exception:
            raise Exception("Exception while Setting version")

    def is_older_state_version(self):
        current_state_version = self.get_state_version()
        if current_state_version < self._state_version:
            return True

    def is_state_compatible(self) -> bool:
        current_state_version = self.get_state_version()
        if current_state_version > self._state_version:
            logger.warning("You have a state with Version %s", current_state_version)
            logger.warning("This node only supports State Version %s", self._state_version)
            return False
        elif self.is_older_state_version():
            logger.warning("Old State Version Found %s", current_state_version)

        return True

    def get_mainchain_height(self) -> int:
        try:
            return int.from_bytes(self._db.get_raw(b'blockheight'), byteorder='big', signed=False)
        except KeyError:
            pass
        except Exception as e:
            logger.error('get_blockheight Exception %s', e)

        return -1

    def update_mainchain_height(self, height, batch):
        self._db.put_raw(b'blockheight', height.to_bytes(8, byteorder='big', signed=False), batch)

    def get_re_org_limit(self) -> int:
        try:
            return int.from_bytes(self._db.get_raw(b'reorg_limit'), byteorder='big', signed=False)
        except KeyError:
            return 0
        except Exception as e:
            logger.error('get_re_org_limit Exception %s', e)

        return -1

    def update_re_org_limit(self, height, batch):
        reorg_limit = height - config.dev.reorg_limit
        if reorg_limit <= 0:
            return
        current_reorg_limit = self.get_re_org_limit()
        if reorg_limit <= current_reorg_limit:
            return
        self._db.put_raw(b'reorg_limit', reorg_limit.to_bytes(8, byteorder='big', signed=False), batch)

    def get_address_is_used(self, address: bytes) -> bool:
        # FIXME: Probably obsolete
        try:
            return self._db.get_raw(address)
        except KeyError:
            return False
        except Exception as e:
            # FIXME: Review
            logger.error('Exception in address_used')
            logger.exception(e)
            raise

    def write_batch(self, batch, sync=True):
        self._db.write_batch(batch, sync)

    #########################################
    #########################################
    #########################################
    #########################################
    #########################################

    def _update_total_coin_supply(self, balance, batch):
        self._db.put_raw(b'total_coin_supply',
                         (self.total_coin_supply + balance).to_bytes(8, byteorder='big', signed=False),
                         batch)

    def _delete(self, key, batch):
        self._db.delete(key, batch)

    def put_dev_config_state(self, dev_config, batch):
        self._db.put_raw(dev_config.current_state_key, dev_config.SerializeToString(), batch)

    def get_dev_config_state(self, dev_config_state_key: bytes):
        try:
            data = self._db.get_raw(dev_config_state_key)
            pbdata = qrl_pb2.DevConfig()
            pbdata.ParseFromString(bytes(data))
            return pbdata
        except KeyError:
            logger.debug('[get_dev_config_state] Dev Config not found')
        except Exception as e:
            logger.error('[get_dev_config_state] %s', e)

        return None

    def get_dev_config_current_state_key(self):
        try:
            return self._db.get_raw(b'dev_config_current_state_key')
        except KeyError:
            logger.debug('[get_dev_config_current_state_key] Dev Config not found')
        except Exception as e:
            logger.error('[get_dev_config_current_state_key] %s', e)

        return None

    def put_dev_config_current_state_key(self, dev_config_state_key: bytes, batch):
        self._db.put_raw(b'dev_config_current_state_key', dev_config_state_key, batch)

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

    @staticmethod
    def generate_token_key(address, token_txhash) -> bytes:
        return b'token_' + address + b'_' + token_txhash

    @staticmethod
    def generate_slave_key(address, slave_pk) -> bytes:
        return b'slave_' + address + b'_' + slave_pk

    def get_token(self, address: bytes, token_txhash: bytes) -> qrl_pb2.TokenBalance:
        try:
            token_balance = qrl_pb2.TokenBalance()
            token_balance.ParseFromString(self._db.get_raw(self.generate_token_key(address, token_txhash)))
            return token_balance
        except KeyError:
            pass
        except Exception as e:
            logger.error('[get_token] %s', e)

        return None

    def put_tokens(self, tokens: dict, batch=None):
        for address_txhash, value in tokens.items():
            token_key = self.generate_token_key(address_txhash[0], address_txhash[1])
            self._db.put_raw(token_key, str(value).encode(), batch)
        return True

    def revert_tokens(self, tokens: dict, batch):
        for address_txhash in tokens:
            token_key = self.generate_token_key(address_txhash[0], address_txhash[1])
            self._db.delete(token_key, batch)
        return True

    def revert_slaves(self, slaves: dict, batch):
        for address, slave_pk in slaves:
            slave_key = self.generate_slave_key(address, slave_pk)
            self._db.delete(slave_key, batch)
        return True

    def put_slaves(self, slaves: dict, batch=None):
        for address_slave_pk in slaves:
            address, slave_pk = address_slave_pk
            slave_key = self.generate_slave_key(address, slave_pk)
            self._db.put_raw(slave_key, str(slaves[address_slave_pk][0]).encode(), batch)

    def get_slave_pk_access_type(self, address: bytes, slave_pk: bytes) -> qrl_pb2.SlaveMetadata:
        slave_key = self.generate_slave_key(address, slave_pk)
        try:
            slave_metadata = qrl_pb2.SlaveMetadata()
            slave_metadata.ParseFromString(self._db.get_raw(slave_key))
            return slave_metadata
        except KeyError:
            pass
        except Exception as e:
            logger.error('[get_slave_pk_access_type] %s', e)

        return None

    def revert_slaves_hash(self, slaves: dict, addresses_state: dict, batch):
        addresses_slave_hashes = dict()
        for address, slave_pk in slaves:
            if address not in addresses_slave_hashes:
                addresses_slave_hashes[address] = self.get_slave_transaction_hashes(address,
                                                                                    addresses_state[address].slaves_count)

            if addresses_slave_hashes[address][-1] != slaves[(address, slave_pk)].tx_hash:
                logger.warning("UnExpected Addresses Slave hashes")
                logger.warning("Expected %s", slaves[(address, slave_pk)][1])
                logger.warning("Found %s", addresses_slave_hashes[address][-1])
                return False

            del addresses_slave_hashes[address][-1]
            address_state = addresses_state[address]
            address_state.update_slaves_count(subtract=True)

            if len(addresses_slave_hashes[address]) == 0:
                self.remove_slave_transaction_hashes(address,
                                                     address_state.slaves_count,
                                                     batch)
                if address_state.slaves_count > 0:
                    addresses_slave_hashes[address] = self.get_slave_transaction_hashes(
                        address, address_state.slaves_count - 1)

        for address in addresses_slave_hashes:
            if addresses_slave_hashes[address]:
                self.put_slave_transaction_hashes(address,
                                                  addresses_state[address].slaves_count,
                                                  addresses_slave_hashes[address],
                                                  batch)

        return True

    def put_slaves_hash(self, slaves: dict, addresses_state: dict, batch=None):
        slave_hashes = dict()
        for address_slave_pk in slaves:
            address, _ = address_slave_pk
            # There could be case where same address associated with multiple
            # slave_pk so full_hashes needs to be loaded only once
            if address not in slave_hashes:
                full_hashes = self.get_slave_transaction_hashes(address, addresses_state[address].slaves_count)
                addresses_state[address].update_slaves_count(len(full_hashes), subtract=True)
                slave_hashes[address] = full_hashes
            slave_hashes[address].append(slaves[address_slave_pk].tx_hash)

        for address in slave_hashes:
            full_hashes = slave_hashes[address]
            start = 0
            hashes = full_hashes[start:start+config.dev.data_per_page]
            address_state = addresses_state[address]
            while hashes:
                address_state.update_slaves_count(len(hashes))
                self.put_slave_transaction_hashes(address, address_state.slaves_count, hashes, batch)
                start += config.dev.data_per_page
                hashes = full_hashes[start:start + config.dev.data_per_page]

    def remove_slave_transaction_hashes(self, address: bytes, page: int, batch=None):
        self._db.delete(b'slave_transaction_hash_' + address + b'_' + str(page).encode(),
                        batch)

    def put_slave_transaction_hashes(self, address: bytes, count: int, hashes: list, batch=None):
        page = count // config.dev.data_per_page
        transaction_hash_list = qrl_pb2.TransactionHashList(hashes=hashes)
        self._db.put_raw(b'slave_transaction_hash_' + address + b'_' + str(page).encode(),
                         transaction_hash_list.SerializeToString(),
                         batch)

    def get_slave_transaction_hashes(self, address: bytes, count: int) -> list:
        page = count // config.dev.data_per_page
        try:
            data = self._db.get_raw(b'slave_transaction_hash_' + address + b'_' + str(page).encode())
            transaction_hash_list = qrl_pb2.TransactionHashList()
            transaction_hash_list.ParseFromString(bytes(data))
            return list(transaction_hash_list.hashes)
        except KeyError:
            return []
        except Exception as e:
            logger.error('Exception in get_slave_transaction_hashes')
            logger.exception(e)
            raise

    def put_tokens_hash(self, tokens: dict, addresses_state: dict, batch=None):
        token_hashes = dict()
        for address_token_tx_hash in tokens:
            address, token_tx_hash = address_token_tx_hash
            # There could be case where same address associated with multiple
            # token_tx_hash so full_hashes needs to be loaded only once
            if address not in token_hashes:
                full_hashes = self.get_token_transaction_hashes(address, addresses_state[address].tokens_count)
                addresses_state[address].update_tokens_count(len(full_hashes), subtract=True)
                token_hashes[address] = full_hashes
            token_hashes[address].append(token_tx_hash)

        for address in token_hashes:
            full_hashes = token_hashes[address]
            start = 0
            hashes = full_hashes[start:start+config.dev.data_per_page]
            address_state = addresses_state[address]
            while hashes:
                self.put_token_transaction_hashes(address, address_state.tokens_count, hashes, batch)
                address_state.update_tokens_count(len(hashes))
                start += config.dev.data_per_page
                hashes = full_hashes[start:start + config.dev.data_per_page]

    def revert_tokens_hash(self, tokens: dict, addresses_state: dict, batch):
        addresses_token_tx_hashes = dict()
        for address_token_tx_hash in tokens:
            address, token_tx_hash = address_token_tx_hash
            if address not in addresses_token_tx_hashes:
                addresses_token_tx_hashes[address] = self.get_token_transaction_hashes(address,
                                                                                       addresses_state[address].tokens_count)

            if addresses_token_tx_hashes[address][-1] != token_tx_hash:
                return False
            del addresses_token_tx_hashes[address][-1]
            address_state = addresses_state[address]
            address_state.update_tokens_count(subtract=True)
            if len(addresses_token_tx_hashes[address]) == 0:
                self.remove_token_transaction_hash(address,
                                                   address_state.tokens_count,
                                                   batch)
                if address_state.tokens_count > 0:
                    addresses_token_tx_hashes[address] = self.get_token_transaction_hashes(
                        address, address_state.tokens_count - 1)

        for address in addresses_token_tx_hashes:
            if addresses_token_tx_hashes[address]:
                self.put_token_transaction_hashes(address,
                                                  addresses_state[address].tokens_count,
                                                  addresses_token_tx_hashes[address],
                                                  batch)

        return True

    def remove_token_transaction_hash(self, address, count, batch):
        page = count // config.dev.data_per_page
        self._db.delete(b'token_transaction_hash_' + address + b'_' + str(page).encode(), batch)

    def put_token_transaction_hashes(self, address: bytes, count: int, hashes: list, batch=None):
        page = count // config.dev.data_per_page
        transaction_hash_list = qrl_pb2.TransactionHashList(hashes=hashes)
        self._db.put_raw(b'token_transaction_hash_' + address + b'_' + str(page).encode(),
                         transaction_hash_list.SerializeToString(),
                         batch)

    def get_token_transaction_hashes(self, address: bytes, count: int) -> list:
        page = count // config.dev.data_per_page
        try:
            data = self._db.get_raw(b'token_transaction_hash_' + address + b'_' + str(page).encode())
            transaction_hash_list = qrl_pb2.TransactionHashList()
            transaction_hash_list.ParseFromString(bytes(data))
            return list(transaction_hash_list.hashes)
        except KeyError:
            return []
        except Exception as e:
            logger.error('Exception in get_token_transaction_hashes')
            logger.exception(e)
            raise
