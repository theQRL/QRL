# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import defaultdict
from typing import Optional
import copy
from twisted.internet import reactor
from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import Qryptominer, PoWHelper, StringToUInt256, UInt256ToString

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.State import State
from qrl.generated import qrl_pb2


class CustomQMiner(Qryptominer):
    def __init__(self, callback):
        Qryptominer.__init__(self)
        self.callback_fn = callback

    def solutionEvent(self, nonce):
        logger.debug('Solution Found %s', nonce)
        try:
            self.callLater_fn.cancel()
        except Exception:
            pass
        self.callback_fn(nonce)


class Miner:
    def __init__(self, pre_block_logic, mining_xmss):
        self.custom_qminer = CustomQMiner(self.mined)
        self.pre_block_logic = pre_block_logic  # FIXME: Circular dependency with node.py
        self.mining_block = None
        self.mining_xmss = mining_xmss
        self.state = None

    def set_state(self, state):
        self.state = state

    def get_mining_data(self, block):
        input_bytes = [0x00, 0x00, 0x00, 0x00] + list(block.mining_hash)
        nonce_offset = 0
        return input_bytes, nonce_offset

    def start_mining(self,
                     tx_pool,
                     parent_block,
                     parent_difficulty,
                     thread_count=config.user.mining_thread_count):
        self.cancel()
        self.mining_block = self.create_block(last_block=parent_block,
                                              mining_nonce=0,
                                              tx_pool=tx_pool,
                                              signing_xmss=self.mining_xmss)
        current_difficulty, current_target = self.calc_difficulty(self.mining_block.timestamp,
                                                                  parent_block.timestamp,
                                                                  parent_difficulty)
        input_bytes, nonce_offset = self.get_mining_data(self.mining_block)
        self.custom_qminer.setInput(input=input_bytes,
                                    nonceOffset=nonce_offset,
                                    target=current_target)
        logger.debug('=================START====================')
        logger.debug('Mine #%s', self.mining_block.block_number)
        logger.debug('block.timestamp %s', self.mining_block.timestamp)
        logger.debug('parent_block.timestamp %s', parent_block.timestamp)
        logger.debug('parent_block.difficulty %s', parent_difficulty)
        logger.debug('input_bytes %s', input_bytes)
        logger.debug('diff : %s | target : %s', current_difficulty, current_target)
        logger.debug('===================END====================')
        self.custom_qminer.start(thread_count=thread_count)

    def mined(self, nonce):
        self.mining_block.set_mining_nonce(nonce)
        logger.info('Block #%s nonce: %s', self.mining_block.block_number, StringToUInt256(str(nonce))[-4:])
        cloned_block = copy.deepcopy(self.mining_block)
        reactor.callLater(0, self.pre_block_logic, cloned_block)

    def cancel(self):
        self.custom_qminer.cancel()

    def create_block(self, last_block, mining_nonce, tx_pool, signing_xmss) -> Optional[Block]:
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        # FIXME: Break encapsulation
        t_pool2 = copy.deepcopy(tx_pool.transaction_pool)
        del tx_pool.transaction_pool[:]
        ######

        # recreate the transaction pool as in the tx_hash_list, ordered by txhash..
        tx_nonce = defaultdict(int)
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

        while txnum < total_txn:
            tx = t_pool2[txnum]
            if tx.ots_key_reuse(addresses_state, tx.ots_key):
                del t_pool2[txnum]
                total_txn -= 1
                continue

            if tx.subtype == qrl_pb2.Transaction.TRANSFER:
                if addresses_state[tx.txfrom].balance < tx.amount:
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
                if tx.owner not in addresses_state:
                    addresses_state[tx.owner] = AddressState.get_default(tx.owner)
                for initial_balance in tx.initial_balances:
                    if initial_balance.address not in addresses_state:
                        addresses_state[initial_balance.address] = AddressState.get_default(initial_balance.address)
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
            tx_nonce[tx.txfrom] += 1
            tx._data.nonce = addresses_state[tx.txfrom].nonce + tx_nonce[tx.txfrom]
            txnum += 1

        block = Block.create(mining_nonce=mining_nonce,
                             block_number=last_block.block_number + 1,
                             prevblock_headerhash=last_block.headerhash,
                             transactions=[],
                             signing_xmss=signing_xmss,
                             nonce=2)

        # reset the pool back
        # FIXME: Reset pool from here?
        tx_pool.transaction_pool = copy.deepcopy(t_pool2)

        return block

    @staticmethod
    def calc_difficulty(timestamp, parent_timestamp, parent_difficulty):
        ph = PoWHelper()
        current_difficulty = ph.getDifficulty(timestamp=timestamp,
                                              parent_timestamp=parent_timestamp,
                                              parent_difficulty=parent_difficulty)
        if int(UInt256ToString(current_difficulty)) <= 1:
            current_difficulty = StringToUInt256("2")
        current_target = ph.getBoundary(current_difficulty)
        return current_difficulty, current_target
