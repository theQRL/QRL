# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import bz2
import os
from decimal import Decimal
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config, logger
from qrl.core.Transaction import Transaction
from qrl.core.Block import Block
from qrl.core.TransactionPool import TransactionPool
from qrl.core.Wallet import Wallet
from qrl.crypto.misc import sha256


class Chain:
    def __init__(self, state):
        self.pstate = state  # FIXME: Is this really a parameter?
        self.chain_dat_filename = os.path.join(config.user.data_path, config.dev.mnemonic_filename)

        self.wallet = Wallet()  # FIXME: Why chain needs access to the wallet?

        self.blockchain = []  # FIXME: Everyone is touching this
        # FIXME: Remove completely and trust the db memcache for this

        # OBSOLETE ????
        self._block_framedata = dict()  # FIXME: this is used to access file chunks. Delete once we move to DB

    @property
    def staking_address(self):
        return self.wallet.address_bundle[0].xmss.get_address().encode()

    @property
    def height(self):
        # FIXME: This will probably get replaced with rocksdb
        if len(self.blockchain):
            return self.blockchain[-1].block_number
        # FIXME: Height cannot be negative. If this is used as an index it should be clarified
        return -1

    def add_block(self, block: Block) -> bool:
        # TODO : minimum block validation in unsynced _state
        if block.block_number <= self.height():
            logger.warning("Block already in the chain")
            return False

        # FIXME: Avoid +1/-1, assign a them to make things clear
        if block.block_number - 1 == self.height():
            if block.prev_headerhash != self.blockchain[-1].headerhash:
                logger.info('prev_headerhash of block doesnt match with headerhash of blockchain')
                return False

        if not self.pstate.add_block_internal(self, block):
            logger.info('last block failed state/stake checks, removed from chain')
            return False

        # FIXME: Check the logig behind these operations
        self.blockchain.append(block)

        # This looks more like optimization/caching
        self.pstate.update_last_tx(block)
        self.pstate.update_tx_metadata(block)
        self.save_chain()

        return True

    def get_block(self, block_idx: int) -> Optional[Block]:
        # Block chain has not been loaded yet?
        # FIXME: Ensure that the chain is already in memory

        if len(self.blockchain) > 0:
            # FIXME: The logic here is not very clear
            inmem_start_idx = self.blockchain[-1].block_number
            inmem_offset = block_idx - inmem_start_idx

            if inmem_offset < 0:
                return self._load_from_file(block_idx)

            if inmem_offset < len(self.blockchain):
                return self.blockchain[inmem_offset]

        return None

    def get_last_block(self) -> Optional[Block]:
        if len(self.blockchain) == 0:
            return None
        return self.blockchain[-1]

    def search(self, query):
        # FIXME: Refactor this. Prepare a look up in the DB
        for block in self.blockchain:
            for protobuf_tx in block.transactions:
                tx = Transaction.from_pbdata(protobuf_tx)
                if tx.txhash == query or tx.txfrom == query or tx.txto == query:
                    logger.info('%s found in block %s', query, str(block.block_number))
                    return tx
        return None

    ###################################
    ###################################
    ###################################
    ###################################
    # Chain Persistence   # TODO: Move to Protobuf/RocksDB

    @staticmethod
    def _get_chain_datafile(epoch):
        # TODO: Persistence will move to rocksdb
        base_dir = os.path.join(config.user.data_path, config.dev.chain_file_directory)
        config.create_path(base_dir)
        return os.path.join(base_dir, 'chain.da' + str(epoch))

    def _load_from_file(self, blocknum):
        # TODO: Persistence will move to rocksdb
        epoch = int(blocknum // config.dev.blocks_per_chain_file)

        block_offset, block_size = self._get_block_metadata(blocknum)

        with open(self._get_chain_datafile(epoch), 'rb') as f:
            f.seek(block_offset)
            json_block = bz2.decompress(f.read(block_size))

            block = Block.from_json(json_block)
            return block

    def _update_block_metadata(self, block_number, block_position, block_size):
        # TODO: Persistence will move to rocksdb
        # FIXME: This is not scalable but it will fine fine for Oct2017 while we replace this with protobuf
        self._block_framedata[block_number] = [block_position, block_size]

    def _get_block_metadata(self, block_number: int):
        # TODO: Persistence will move to rocksdb
        # FIXME: This is not scalable but it will fine fine for Oct2017 while we replace this with protobuf
        return self._block_framedata[block_number]

    def _read_chain(self, epoch):
        # TODO: Persistence will move to rocksdb
        delimiter = config.dev.binary_file_delimiter
        chunk_filename = self._get_chain_datafile(epoch)
        block_list = []

        if os.path.isfile(chunk_filename):
            try:
                with open(chunk_filename, 'rb') as myfile:
                    json_block = bytearray()
                    tmp = bytearray()
                    count = 0
                    offset = 0
                    while True:
                        chars = myfile.read(config.dev.chain_read_buffer_size)
                        for char in chars:
                            offset += 1
                            if count > 0 and char != delimiter[count]:
                                count = 0
                                json_block += tmp
                                tmp = bytearray()
                            if char == delimiter[count]:
                                tmp.append(delimiter[count])
                                count += 1
                                if count < len(delimiter):
                                    continue
                                tmp = bytearray()
                                count = 0
                                pos = offset - len(delimiter) - len(json_block)
                                json_block = bz2.decompress(json_block)

                                block = Block.from_json(json_block)

                                self._update_block_metadata(block.block_number, pos, len(json_block))

                                block_list.append(block)

                                json_block = bytearray()
                                continue
                            json_block.append(char)
                        if len(chars) < config.dev.chain_read_buffer_size:
                            break
            except Exception as e:
                logger.error('IO error %s', e)
                block_list = []

        return block_list

    def save_chain(self):
        # TODO: Persistence will move to rocksdb
        if (self.blockchain[-1].block_number + 1) % config.dev.disk_writes_after_x_blocks == 0:
            # FIXME: Direct access... refactor
            blocknumber = self.blockchain[-1].block_number
            file_epoch = int(blocknumber // config.dev.blocks_per_chain_file)
            writeable = self.blockchain[-config.dev.disk_writes_after_x_blocks:]
            logger.debug('Writing chain to disk')

            with open(self._get_chain_datafile(file_epoch), 'ab') as myfile:
                for block in writeable:
                    json_block = bytes(block.to_json(), 'utf-8')
                    compressed_block = bz2.compress(json_block, config.dev.compression_level)
                    block_pos = myfile.tell()
                    block_size = len(compressed_block)

                    self._update_block_metadata(block.block_number, block_pos, block_size)

                    myfile.write(compressed_block)
                    myfile.write(config.dev.binary_file_delimiter)

            del self.blockchain[:-1]

    ###################################
    ###################################
    ###################################
    ###################################

    @staticmethod
    def score(stake_address,
              reveal_one: bytes,
              balance: int = 0,
              seed: bytes = None,
              verbose: bool = False):
        # TODO: This seems more related to POS logic and is static. Can we move it formulas?
        if not seed:
            logger.info('Exception Raised due to seed none in score fn')
            raise Exception

        if not balance:
            logger.info(' balance 0 so score none ')
            logger.info(' stake_address %s', stake_address)
            return None
        reveal_seed = bin2hstr(sha256(str(reveal_one).encode() + str(seed).encode()))
        score = (Decimal(config.dev.N) - (Decimal(int(reveal_seed, 16)).log10() / Decimal(2).log10())) / Decimal(
            balance)

        if verbose:
            logger.info('=' * 10)
            logger.info('Score - %s', score)
            logger.info('reveal_one - %s', reveal_one)
            logger.info('seed - %s', seed)
            logger.info('balance - %s', balance)

        return score
