# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import Qryptominer, PoWHelper, StringToUInt256, UInt256ToString, Qryptonight

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.misc import logger
from qrl.generated import qrl_pb2


class Miner(Qryptominer):
    def __init__(self, pre_block_logic, mining_xmss, state):
        super().__init__()
        self.pre_block_logic = pre_block_logic  # FIXME: Circular dependency with node.py
        self._mining_block = None
        self._mining_xmss = mining_xmss
        self.state = state

    @staticmethod
    def _get_mining_data(block):
        input_bytes = [0x00, 0x00, 0x00, 0x00] + list(block.mining_hash)
        nonce_offset = 0
        return input_bytes, nonce_offset

    @staticmethod
    def calc_difficulty(timestamp, parent_timestamp, parent_difficulty):
        ph = PoWHelper(kp=100,
                       set_point=60)

        ph.clearTimestamps()
        ph.addTimestamp(parent_timestamp)
        current_difficulty = ph.getDifficulty(timestamp=timestamp,
                                              parent_difficulty=parent_difficulty)
        current_target = ph.getBoundary(current_difficulty)
        return current_difficulty, current_target

    @staticmethod
    def calc_hash(input_bytes):
        qn = Qryptonight()
        return qn.hash(input_bytes)

    def start_mining(self,
                     tx_pool,
                     parent_block,
                     parent_difficulty,
                     thread_count=config.user.mining_thread_count):
        try:
            self.cancel()
            self._mining_block = self.create_block(last_block=parent_block,
                                                   mining_nonce=0,
                                                   tx_pool=tx_pool,
                                                   signing_xmss=self._mining_xmss)

            current_difficulty, current_target = self.calc_difficulty(self._mining_block.timestamp,
                                                                      parent_block.timestamp,
                                                                      parent_difficulty)

            input_bytes, nonce_offset = self._get_mining_data(self._mining_block)
            logger.debug('=================START====================')
            logger.debug('Mine #%s', self._mining_block.block_number)
            logger.debug('block.timestamp %s', self._mining_block.timestamp)
            logger.debug('parent_block.timestamp %s', parent_block.timestamp)
            logger.debug('parent_block.difficulty %s', UInt256ToString(parent_difficulty))
            logger.debug('input_bytes %s', UInt256ToString(input_bytes))
            logger.debug('diff : %s | target : %s', UInt256ToString(current_difficulty), current_target)
            logger.debug('===================END====================')
            self.start(input=input_bytes,
                       nonceOffset=nonce_offset,
                       target=current_target,
                       thread_count=thread_count)
        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

    def solutionEvent(self, nonce):
        # NOTE: This function usually runs in the context of a C++ thread
        try:
            logger.debug('Solution Found %s', nonce)
            self._mining_block.set_mining_nonce(nonce)
            logger.info('Block #%s nonce: %s', self._mining_block.block_number, StringToUInt256(str(nonce))[-4:])
            cloned_block = copy.deepcopy(self._mining_block)
            self.pre_block_logic(cloned_block)
        except Exception as e:
            logger.warning("Exception in solutionEvent")
            logger.exception(e)

    def create_block(self, last_block, mining_nonce, tx_pool, signing_xmss) -> Optional[Block]:
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        # FIXME: Break encapsulation
        t_pool2 = copy.deepcopy(tx_pool.transaction_pool)
        del tx_pool.transaction_pool[:]
        ######

        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        total_txn = len(t_pool2)
        txnum = 0
        addresses_set = set()
        while txnum < total_txn:
            tx = t_pool2[txnum]
            tx.set_effected_address(addresses_set)
            txnum += 1

        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self.state.get_address(address)

        block_size = qrl_pb2.Block().ByteSize()
        block_size_limit = self.state.get_block_size_limit(last_block)
        txnum = 0
        while txnum < total_txn:
            tx = t_pool2[txnum]
            # Skip Transactions for later, which doesn't fit into block
            if block_size + tx.size > block_size_limit:
                txnum += 1
                continue
            if tx.ots_key_reuse(addresses_state[tx.txfrom], tx.ots_key):
                del t_pool2[txnum]
                total_txn -= 1
                continue

            if tx.subtype == qrl_pb2.Transaction.TRANSFER:
                if addresses_state[tx.txfrom].balance < tx.amount + tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s', addresses_state[tx.txfrom].balance,
                                   tx.amount)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.MESSAGE:
                if addresses_state[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid message tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Free %s', addresses_state[tx.txfrom].balance, tx.fee)
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.TOKEN:
                if addresses_state[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Fee %s',
                                   addresses_state[tx.txfrom].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.TRANSFERTOKEN:
                if addresses_state[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   addresses_state[tx.txfrom].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if bin2hstr(tx.token_txhash).encode() not in addresses_state[tx.txfrom].tokens:
                    logger.warning('%s doesnt own any token with token_txnhash %s', tx.txfrom,
                                   bin2hstr(tx.token_txhash).encode())
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if addresses_state[tx.txfrom].tokens[bin2hstr(tx.token_txhash).encode()] < tx.amount:
                    logger.warning('Token Transfer amount exceeds available token')
                    logger.warning('Token Txhash %s', bin2hstr(tx.token_txhash).encode())
                    logger.warning('Available Token Amount %s',
                                   addresses_state[tx.txfrom].tokens[bin2hstr(tx.token_txhash).encode()])
                    logger.warning('Transaction Amount %s', tx.amount)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if tx.subtype == qrl_pb2.Transaction.LATTICE:
                if addresses_state[tx.txfrom].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.txfrom)
                    logger.warning('subtype: %s', tx.subtype)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   addresses_state[tx.txfrom].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            tx.apply_on_state(addresses_state)

            tx_pool.add_tx_to_pool(tx)
            tx._data.nonce = addresses_state[tx.txfrom].nonce
            txnum += 1

        coinbase_nonce = self.state.get_address(signing_xmss.get_address()).nonce
        if signing_xmss.get_address() in addresses_state:
            coinbase_nonce = addresses_state[signing_xmss.get_address()].nonce + 1

        block = Block.create(mining_nonce=mining_nonce,
                             block_number=last_block.block_number + 1,
                             prevblock_headerhash=last_block.headerhash,
                             transactions=t_pool2,
                             signing_xmss=signing_xmss,
                             nonce=coinbase_nonce)

        return block
