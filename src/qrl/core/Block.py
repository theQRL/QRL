# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict
from statistics import median
from typing import Optional

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.config import DevConfig
from qrl.core.misc import logger, ntp
from qrl.core.State import State
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.BlockHeader import BlockHeader
from qrl.crypto.misc import merkle_tx_hash
from qrl.crypto.Qryptonight import Qryptonight
from qrl.generated import qrl_pb2


class Block(object):
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.Block()

        self.blockheader = BlockHeader(self._data.header)

    def __eq__(self, other):
        equality = (self.block_number == other.block_number) and (self.headerhash == other.headerhash) and (
                self.prev_headerhash == other.prev_headerhash) and (self.timestamp == other.timestamp) and (
                           self.mining_nonce == other.mining_nonce)
        return equality

    @property
    def size(self):
        return self._data.ByteSize()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf Block object
        :rtype: qrl_pb2.Block
        """
        return self._data

    @property
    def block_number(self):
        return self.blockheader.block_number

    @property
    def headerhash(self):
        return self.blockheader.headerhash

    @property
    def prev_headerhash(self):
        return self.blockheader.prev_headerhash

    @property
    def transactions(self):
        return self._data.transactions

    @property
    def mining_nonce(self):
        return self.blockheader.mining_nonce

    @property
    def block_reward(self):
        return self.blockheader.block_reward

    @property
    def fee_reward(self):
        return self.blockheader.fee_reward

    @property
    def timestamp(self):
        return self.blockheader.timestamp

    def mining_blob(self, dev_config: DevConfig) -> bytes:
        return self.blockheader.mining_blob(dev_config)

    def mining_nonce_offset(self, dev_config: DevConfig) -> bytes:
        return self.blockheader.nonce_offset(dev_config)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Block()
        Parse(json_data, pbdata)
        return Block(pbdata)

    def verify_blob(self, blob: bytes, dev_config: DevConfig) -> bool:
        return self.blockheader.verify_blob(blob, dev_config)

    def set_nonces(self, dev_config: DevConfig, mining_nonce: int, extra_nonce: int = 0):
        self.blockheader.set_nonces(dev_config, mining_nonce, extra_nonce)
        self._data.header.MergeFrom(self.blockheader.pbdata)

    def to_json(self) -> str:
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data, sort_keys=True)

    def serialize(self) -> str:
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrl_pb2.Block()
        pbdata.ParseFromString(bytes(data))
        block = Block(pbdata)
        return block

    @staticmethod
    def _copy_tx_pbdata_into_block(block, tx):
        block._data.transactions.extend([tx.pbdata])

    @staticmethod
    def create(dev_config: DevConfig,
               block_number: int,
               prev_headerhash: bytes,
               prev_timestamp: int,
               transactions: list,
               miner_address: bytes,
               seed_height: Optional[int],
               seed_hash: Optional[bytes]):

        block = Block()

        # Process transactions
        hashedtransactions = []
        fee_reward = 0

        for tx in transactions:
            fee_reward += tx.fee

        # Prepare coinbase tx
        total_reward_amount = BlockHeader.block_reward_calc(block_number, dev_config) + fee_reward
        coinbase_tx = CoinBase.create(dev_config, total_reward_amount, miner_address, block_number)
        hashedtransactions.append(coinbase_tx.txhash)
        Block._copy_tx_pbdata_into_block(block, coinbase_tx)  # copy memory rather than sym link

        for tx in transactions:
            hashedtransactions.append(tx.txhash)
            Block._copy_tx_pbdata_into_block(block, tx)  # copy memory rather than sym link

        txs_hash = merkle_tx_hash(hashedtransactions)  # FIXME: Find a better name, type changes

        tmp_blockheader = BlockHeader.create(dev_config=dev_config,
                                             blocknumber=block_number,
                                             prev_headerhash=prev_headerhash,
                                             prev_timestamp=prev_timestamp,
                                             hashedtransactions=txs_hash,
                                             fee_reward=fee_reward,
                                             seed_height=seed_height,
                                             seed_hash=seed_hash)

        block.blockheader = tmp_blockheader

        block._data.header.MergeFrom(tmp_blockheader.pbdata)

        block.set_nonces(dev_config, 0, 0)

        return block

    def update_mining_address(self, dev_config: DevConfig, mining_address: bytes):
        coinbase_tx = Transaction.from_pbdata(self.transactions[0])
        coinbase_tx.update_mining_address(mining_address)
        hashedtransactions = []

        for tx in self.transactions:
            hashedtransactions.append(tx.transaction_hash)

        self.blockheader.update_merkle_root(dev_config, merkle_tx_hash(hashedtransactions))

        self._data.header.MergeFrom(self.blockheader.pbdata)

    def validate(self, chain_manager, future_blocks: OrderedDict) -> bool:
        if chain_manager.get_block_is_duplicate(self):
            logger.warning('Duplicate Block #%s %s', self.block_number, bin2hstr(self.headerhash))
            return False

        parent_block = chain_manager.get_block(self.prev_headerhash)
        dev_config = chain_manager.get_config_by_block_number(self.block_number)

        # If parent block not found in state, then check if its in the future block list
        if not parent_block:
            try:
                parent_block = future_blocks[self.prev_headerhash]
            except KeyError:
                logger.warning('Parent block not found')
                logger.warning('Parent block headerhash %s', bin2hstr(self.prev_headerhash))
                return False

        if not self._validate_parent_child_relation(parent_block):
            logger.warning('Failed to validate blocks parent child relation')
            return False

        if not chain_manager.validate_mining_nonce(self.blockheader, dev_config):
            logger.warning('Failed PoW Validation')
            return False

        if len(self.transactions) == 0:
            return False

        try:
            state_container = chain_manager.new_state_container(set(),
                                                                self.block_number,
                                                                False,
                                                                None)

            coinbase_txn = Transaction.from_pbdata(self.transactions[0])
            coinbase_amount = coinbase_txn.amount

            if not coinbase_txn.validate_all(state_container):
                return False

            if self.block_number != 2078158:
                for proto_tx in self.transactions[1:]:
                    if proto_tx.WhichOneof('transactionType') == 'coinbase':
                        logger.warning("Multiple coinbase transaction found")
                        return False

        except Exception as e:
            logger.warning('Exception %s', e)
            return False

        # Build transaction merkle tree, calculate fee reward, and then see if BlockHeader also agrees.
        hashedtransactions = []

        for tx in self.transactions:
            tx = Transaction.from_pbdata(tx)
            hashedtransactions.append(tx.txhash)

        fee_reward = 0
        for index in range(1, len(self.transactions)):
            fee_reward += self.transactions[index].fee

        qn = Qryptonight()
        seed_block = chain_manager.get_block_by_number(qn.get_seed_height(self.block_number))

        self.blockheader._seed_height = seed_block.block_number
        self.blockheader._seed_hash = seed_block.headerhash

        if not self.blockheader.validate(fee_reward,
                                         coinbase_amount,
                                         merkle_tx_hash(hashedtransactions),
                                         dev_config):
            return False

        return True

    def is_future_block(self, dev_config: DevConfig) -> bool:
        if self.timestamp > ntp.getTime() + dev_config.block_max_drift:
            return True

        return False

    def _validate_parent_child_relation(self, parent_block) -> bool:
        return self.blockheader.validate_parent_child_relation(parent_block)

    @staticmethod
    def put_block(state: State, block, batch):
        state._db.put_raw(block.headerhash, block.serialize(), batch)

    @staticmethod
    def get_block(state: State, header_hash: bytes):
        try:
            data = state._db.get_raw(header_hash)
            return Block.deserialize(data)
        except KeyError:
            logger.debug('[get_block] Block header_hash %s not found', bin2hstr(header_hash).encode())
        except Exception as e:
            logger.error('[get_block] %s', e)

        return None

    @staticmethod
    def get_block_size_limit(state: State, block, dev_config: DevConfig):
        # NOTE: Miner
        block_size_list = []
        for _ in range(0, 10):
            block = Block.get_block(state, block.prev_headerhash)
            if not block:
                return None
            block_size_list.append(block.size)
            if block.block_number == 0:
                break
        return max(dev_config.block_min_size_limit_in_bytes, dev_config.size_multiplier * median(block_size_list))

    @staticmethod
    def remove_blocknumber_mapping(state: State, block_number, batch):
        state._db.delete(str(block_number).encode(), batch)

    @staticmethod
    def put_block_number_mapping(state: State, block_number: int, block_number_mapping, batch):
        state._db.put_raw(str(block_number).encode(), MessageToJson(block_number_mapping, sort_keys=True).encode(), batch)

    @staticmethod
    def get_block_number_mapping(state: State, block_number: int):
        try:
            data = state._db.get_raw(str(block_number).encode())
            block_number_mapping = qrl_pb2.BlockNumberMapping()
            return Parse(data, block_number_mapping)
        except KeyError:
            logger.debug('[get_block_number_mapping] Block #%s not found', block_number)
        except Exception as e:
            logger.error('[get_block_number_mapping] %s', e)

        return None

    @staticmethod
    def get_block_by_number(state: State, block_number: int):
        block_number_mapping = Block.get_block_number_mapping(state, block_number)
        if not block_number_mapping:
            return None
        return Block.get_block(state, block_number_mapping.headerhash)

    @staticmethod
    def get_block_header_hash_by_number(state: State, block_number: int):
        block_number_mapping = Block.get_block_number_mapping(state, block_number)
        if not block_number_mapping:
            return None
        return block_number_mapping.headerhash

    @staticmethod
    def last_block(state: State):
        block_number = state.get_mainchain_height()
        return Block.get_block_by_number(state, block_number)
