# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import bz2
import os
from typing import Optional, Dict

from qrl.core import config, logger
from qrl.core.Block import Block
from qrl.core.StakeValidatorsTracker import StakeValidatorsTracker
from qrl.core.AddressState import AddressState
from qrl.core.Transaction import Transaction
from qrl.core.Wallet import Wallet


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
        # FIXME: This is bad, height is not height but max index
        if len(self.blockchain):
            return self.blockchain[-1].block_number
        return 0

    def add_block(self,
                  block: Block,
                  address_state_dict: Dict[bytes, AddressState],
                  stake_validators_tracker: StakeValidatorsTracker,
                  next_seed,
                  slave_xmss) -> bool:
        # TODO : minimum block validation in unsynced _state
        if block.block_number < self.height:
            logger.warning("Block already in the chain")
            return False

        if self.height > 0:
            prev_block = self.blockchain[-1]
            if block.block_number != prev_block.block_number + 1:
                logger.warning('main: Block {} rejected. prev_block is not available.'.format(block.block_number))
                return False

            if prev_block.headerhash != block.prev_headerhash:
                logger.warning('main: Block {} rejected. prevheaderhash mismatch'.format(block.block_number))
                return False

        logger.debug('%s %s tx passed verification.', block.headerhash, len(block.transactions))

        self._commit(block=block,
                     address_state_dict=address_state_dict,
                     stake_validators_tracker=stake_validators_tracker,
                     next_seed=next_seed,
                     slave_xmss=slave_xmss)

        return True

    def _commit(self,
                block: Block,
                address_state_dict: Dict[bytes, AddressState],
                stake_validators_tracker: StakeValidatorsTracker,
                next_seed,
                slave_xmss,
                ignore_save_wallet=False):

        # FIXME: Check the logig behind these operations
        self.blockchain.append(block)

        batch = self.pstate.get_batch()

        self.pstate.update_vote_metadata(block, batch)  # This has to be updated, before the pstate stake_validators

        self.pstate.update_stake_validators(stake_validators_tracker)

        for address in address_state_dict:
            self.pstate._save_address_state(address_state_dict[address], batch)

        for dup_tx in block.duplicate_transactions:
            if dup_tx.coinbase1.txto in self.pstate.stake_validators_tracker.sv_dict:
                # FIXME: Setting the property is invalid
                self.pstate.stake_validators_tracker.sv_dict[dup_tx.coinbase1.txto]._is_banned = True

        # This looks more like optimization/caching
        self.pstate.update_last_tx(block, batch)
        self.pstate.update_tx_metadata(block, batch)
        self.pstate.write_stake_validators_tracker(batch)
        self.pstate.write_prev_stake_validators_tracker(batch)
        self.pstate.update_next_seed(next_seed, batch)
        self.pstate.update_state_version(block.block_number, batch)
        self.pstate.update_slave_xmss(slave_xmss, batch)
        self.pstate.put_block(block, batch)
        self.pstate.write_batch(batch)

        if not ignore_save_wallet:
            self.wallet.save_wallet()

        logger.debug('#%s[%s]\nWinner Stake Selector: %s has been committed.',
                     block.block_number,
                     block.headerhash,
                     block.stake_selector)

        return True

    def load_state(self) -> bool:
        try:
            self.pstate.prev_stake_validators_tracker = StakeValidatorsTracker.from_json(self.pstate.get_prev_stake_validators_tracker())
            self.pstate.stake_validators_tracker = StakeValidatorsTracker.from_json(self.pstate.get_stake_validators_tracker())

            block_number = self.pstate.get_state_version()
            block = Block.from_json(self.pstate.get_block(block_number))
            self.blockchain.append(block)

            return True
        except Exception:
            return False

    def get_block(self, block_idx: int) -> Optional[Block]:
        # Block chain has not been loaded yet?
        # FIXME: Ensure that the chain is already in memory

        if len(self.blockchain) > 0:
            # FIXME: The logic here is not very clear
            inmem_start_idx = self.blockchain[0].block_number
            inmem_offset = block_idx - inmem_start_idx

            if inmem_offset < 0:
                return Block.from_json(self.pstate.get_block(block_idx))

            if inmem_offset < len(self.blockchain):
                return self.blockchain[inmem_offset]

        return None

    def get_transaction(self, transaction_hash)->Optional[Transaction]:
        answer = self.pstate.get_tx_metadata(transaction_hash)
        if answer is None:
            return None
        else:
            tx, _ = answer
        return tx

    # FIXME: We need a clear database schema
    def get_blockidx_from_txhash(self, transaction_hash):
        answer = self.pstate.get_tx_metadata(transaction_hash)
        if answer is None:
            return None
        else:
            _, block_index = answer
        return block_index

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
