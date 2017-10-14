# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import simplejson as json

from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_COINBASE, TX_SUBTYPE_TX
from qrl.core import logger, config
from qrl.core.blockheader import BlockHeader
from qrl.core.helper import select_target_hashchain
from qrl.core.Transaction import Transaction, CoinBase, DuplicateTransaction
from qrl.crypto.misc import sha256, merkle_tx_hash


class Block(object):
    def __init__(self):
        self.blockheader = None
        self.transactions = None
        self.duplicate_transactions = None

        self.state = None
        self.stake_list = None

    def create(self, chain, reveal_hash, vote_hash, last_block_number=-1):
        # FIXME: probably this should turn into a constructor
        reveal_hash = reveal_hash
        vote_hash = vote_hash

        data = None
        if last_block_number == -1:
            data = chain.block_chain_buffer.get_last_block()  # m_get_last_block()
        else:
            data = chain.block_chain_buffer.get_block_n(last_block_number)

        last_block_number = data.blockheader.blocknumber
        prev_blockheaderhash = data.blockheader.headerhash

        hashedtransactions = []
        self.transactions = [None]
        fee_reward = 0

        for tx in chain.transaction_pool:
            if tx.subtype == TX_SUBTYPE_TX:
                fee_reward += tx.fee
            hashedtransactions.append(tx.txhash)
            self.transactions.append(tx)  # copy memory rather than sym link

        self.duplicate_transactions = []

        for tx in chain.duplicate_tx_pool:
            self.duplicate_transactions.append(chain.duplicate_tx_pool[tx])

        if not hashedtransactions:
            hashedtransactions = [sha256('')]

        hashedtransactions = merkle_tx_hash(hashedtransactions)

        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain,
                                blocknumber=last_block_number + 1,
                                reveal_hash=reveal_hash,
                                vote_hash=vote_hash,
                                prev_blockheaderhash=prev_blockheaderhash,
                                hashedtransactions=hashedtransactions,
                                fee_reward=fee_reward)

        signing_xmss = chain.block_chain_buffer.get_slave_xmss(last_block_number + 1)

        coinbase_tx = CoinBase.create(self.blockheader, signing_xmss)

        coinbase_tx.sign(signing_xmss)

        self.transactions[0] = coinbase_tx
        sv_list = chain.block_chain_buffer.get_stake_validators_list(last_block_number + 1).sv_list
        coinbase_tx.nonce = sv_list[chain.mining_address].nonce + 1

    def validate_block(self, chain):  # check validity of new block..
        """
        block validation
        :param chain:
        :return:
        """

        try:
            blk_header = self.blockheader
            last_blocknum = blk_header.blocknumber - 1
            last_block = chain.block_chain_buffer.get_block_n(last_blocknum)

            if not self.blockheader.validate(last_block.blockheader):
                return False

            if len(self.transactions) == 0:
                logger.warning('BLOCK : There must be atleast 1 txn')
                return False

            coinbase_tx = self.transactions[0]

            if coinbase_tx.subtype != TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False

            sv_list = chain.block_chain_buffer.stake_list_get(self.blockheader.blocknumber)

            if coinbase_tx.txto != bytes(self.blockheader.stake_selector.encode()):
                logger.info('Non matching txto and stake_selector')
                logger.info('txto: %s stake_selector %s', coinbase_tx.txfrom, self.blockheader.stake_selector)
                return False

            if coinbase_tx.amount != self.blockheader.block_reward + self.blockheader.fee_reward:
                logger.info('Block_reward doesnt match')
                logger.info('Found: %s', coinbase_tx.amount)
                logger.info('Expected: %s', self.blockheader.block_reward + self.blockheader.fee_reward)
                logger.info('block_reward: %s', self.blockheader.block_reward)
                logger.info('fee_reward: %s', self.blockheader.fee_reward)
                return False

            if blk_header.blocknumber == 1:
                found = False
                for tx in self.transactions:
                    if tx.subtype == TX_SUBTYPE_STAKE:
                        if tx.txfrom == bytes(blk_header.stake_selector.encode()):
                            found = True
                            reveal_hash, vote_hash = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash,
                                                                            self.transactions[0].txto,
                                                                            tx.hash, blocknumber=1)

                            if sha256(blk_header.reveal_hash) != reveal_hash:
                                logger.warning('reveal_hash does not hash correctly to terminator: failed validation')
                                return False

                if not found:
                    logger.warning('Stake selector not in block.stake: failed validation')
                    return False

            else:  # we look in stake_list for the hash terminator and hash to it..
                stake_validators_list = chain.block_chain_buffer.get_stake_validators_list(self.blockheader.blocknumber)
                if self.transactions[0].txto not in stake_validators_list.sv_list:
                    logger.warning('Stake selector not in stake_list for this epoch..')
                    return False

                if not stake_validators_list.validate_hash(blk_header.reveal_hash,
                                                           blk_header.blocknumber,
                                                           config.dev.hashchain_nums - 1,
                                                           self.transactions[0].txto):
                    logger.warning('Supplied hash does not iterate to terminator: failed validation')
                    return False

                target_chain = select_target_hashchain(blk_header.prev_blockheaderhash)

                if not stake_validators_list.validate_hash(blk_header.vote_hash,
                                                           blk_header.blocknumber,
                                                           target_chain,
                                                           self.transactions[0].txto):
                    logger.warning('Not all the reveal_hashes are valid..')
                    return False

            if not self._validate_tx_in_block(chain):
                logger.warning('Block validate_tx_in_block error: failed validation')
                return False

        except Exception as e:
            logger.exception(e)
            return False

        return True

    def _validate_tx_in_block(self, chain):
        # Validating coinbase txn
        coinbase_txn = self.transactions[0]
        valid = coinbase_txn.validate_tx(chain=chain,
                                         blockheader=self.blockheader)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_num in range(1, len(self.transactions)):
            tx = self.transactions[tx_num]
            if not tx.validate_tx():
                logger.warning('invalid tx in block')
                logger.warning('subtype: %s txhash: %s txfrom: %s', tx.subtype, tx.txhash, tx.txfrom)
                return False

        for tx in self.duplicate_transactions:
            if not tx.validate_tx():
                logger.warning('invalid duplicate tx in block')
                logger.warning('txhash: %s tx_stake_selector: %s', tx.get_message_hash(), tx.coinbase1.txto)
                return False

        return True

    @staticmethod
    def from_json(json_block):
        """
        Constructor a block from a json string
        :param json_block: a block serialized as a json string
        :return: A block
        """
        tmp_block = Block()
        json_block = json.loads(json_block)
        tmp_block.blockheader = BlockHeader.from_json(json_block['blockheader'])

        if tmp_block.blockheader.blocknumber == 0:
            tmp_block.state = json_block['state']
            tmp_block.stake_list = json_block['stake_list']

        json_transactions = json_block['transactions']
        json_duplicate_transactions = json_block['duplicate_transactions']

        tmp_block.transactions = [Transaction.from_txdict(tx) for tx in json_transactions]
        tmp_block.duplicate_transactions = [DuplicateTransaction().from_txdict(tx)
                                            for tx in json_duplicate_transactions]

        return tmp_block
