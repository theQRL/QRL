# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import simplejson as json

from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_COINBASE, TX_SUBTYPE_TX
from qrl.core import logger, config, ntp
from qrl.core.blockheader import BlockHeader
from qrl.core.helper import select_target_hashchain
from qrl.core.Transaction import Transaction, CoinBase, DuplicateTransaction
from qrl.crypto.misc import sha256, merkle_tx_hash


class Block(object):
    @staticmethod
    def isHashPresent(txhash, buffer, blocknumber):
        """
        :param txhash:
        :type txhash:
        :param buffer:
        :type buffer:
        :param blocknumber:
        :type blocknumber:
        :return:
        :rtype:
        >>> Block.isHashPresent(None, None, None)
        False
        """
        if not buffer:
            return False

        min_blocknum = min(buffer)
        max_blocknum = min(blocknumber - 1, max(buffer))

        for blocknum in range(min_blocknum, max_blocknum + 1):
            if txhash in buffer[blocknum]:
                return True

        return False

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

        coinbase_tx = CoinBase().create(self.blockheader,
                                        chain.block_chain_buffer.get_slave_xmss(last_block_number + 1))
        #coinbase_tx = CoinBase().create(self.blockheader.block_reward + self.blockheader.fee_reward,
        #                                            self.blockheader.headerhash,
        #                                            chain.wallet.address_bundle[0].xmss.get_address(),
        #                                            chain.block_chain_buffer.get_slave_xmss(last_block_number + 1))

        self.transactions[0] = coinbase_tx
        sv_list = chain.block_chain_buffer.get_stake_validators_list(last_block_number + 1).sv_list
        coinbase_tx.nonce = sv_list[chain.mining_address].nonce + 1

    def json_to_block(self, json_block):
        self.blockheader = BlockHeader()
        self.blockheader.json_to_blockheader(json_block['blockheader'])

        transactions = json_block['transactions']
        self.transactions = []
        for tx in transactions:
            self.transactions.append(Transaction.from_txdict(tx))

        duplicate_transactions = json_block['duplicate_transactions']
        self.duplicate_transactions = []
        for tx in duplicate_transactions:
            self.duplicate_transactions.append(DuplicateTransaction().from_txdict(tx))

        if self.blockheader.blocknumber == 0:
            self.state = json_block['state']
            self.stake_list = json_block['stake_list']

    @staticmethod
    def from_json(json_block):
        """
        Constructor a block from a json string
        :param json_block: a block serialized as a json string
        :return: A block
        """
        tmp_block = Block()
        tmp_block.json_to_block(json.loads(json_block))
        return tmp_block

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
                logger.warning('txhash: %s tx_stake_selector: %s', tx.get_message_hash(), tx.stake_selector)
                return False

        return True

    def validate_block(self, chain):  # check validity of new block..
        """
        block validation
        :param chain:
        :return:
        """
        b = self.blockheader
        last_blocknum = b.blocknumber - 1
        tmp_last_block = chain.block_chain_buffer.get_block_n(last_blocknum)

        curr_timestamp = ntp.getTime()

        if b.timestamp <= tmp_last_block.blockheader.timestamp:
            logger.warning('BLOCK timestamp is less than prev block timestamp')
            logger.warning('block timestamp %s ', b.timestamp)
            logger.warning('must be greater than %s', tmp_last_block.blockheader.timestamp)
            return False

        if b.generate_headerhash() != b.headerhash:
            logger.warning('Headerhash false for block: failed validation')
            return False

        if tmp_last_block.blockheader.timestamp + config.dev.minimum_minting_delay > b.timestamp:
            logger.warning('BLOCK created without waiting for minimum minting delay')
            logger.warning('prev_block timestamp %s ', tmp_last_block.blockheader.timestamp)
            logger.warning('current_block timestamp %s ', b.timestamp)
            return False

        if tmp_last_block.blockheader.headerhash != b.prev_blockheaderhash:
            logger.warning('Headerhash not in sequence: failed validation')
            return False

        if tmp_last_block.blockheader.blocknumber != b.blocknumber - 1:
            logger.warning('Block numbers out of sequence: failed validation')
            return False

        if len(self.transactions) == 0:
            logger.warning('BLOCK : There must be atleast 1 txn')
            return False

        coinbase_tx = self.transactions[0]

        try:
            if coinbase_tx.subtype != TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False
        except Exception as e:
            logger.exception(e)
            return False

        sv_list = chain.block_chain_buffer.stake_list_get(self.blockheader.blocknumber)

        if coinbase_tx.txto != self.blockheader.stake_selector:
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

        if b.timestamp == 0 and b.blocknumber > 0:
            logger.warning('Invalid block timestamp ')
            return False

        if b.block_reward != b.block_reward_calc():
            logger.warning('Block reward incorrect for block: failed validation')
            return False

        if b.epoch != b.blocknumber // config.dev.blocks_per_epoch:
            logger.warning('Epoch incorrect for block: failed validation')
            return False

        if b.blocknumber == 1:
            x = 0
            for tx in self.transactions:
                if tx.subtype == TX_SUBTYPE_STAKE:
                    if tx.txfrom == b.stake_selector:
                        x = 1
                        reveal_hash, vote_hash = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash,
                                                                        self.transactions[0].txto,
                                                                        tx.hash, blocknumber=1)

                        if sha256(b.reveal_hash) != reveal_hash:
                            logger.warning('reveal_hash does not hash correctly to terminator: failed validation')
                            return False

                        if sha256(b.vote_hash) != vote_hash:
                            logger.warning('vote_hash does not hash correctly to terminator: failed validation')
                            return False
            if x != 1:
                logger.warning('Stake selector not in block.stake: failed validation')
                return False
        else:  # we look in stake_list for the hash terminator and hash to it..
            stake_validators_list = chain.block_chain_buffer.get_stake_validators_list(self.blockheader.blocknumber)
            if self.transactions[0].txto not in stake_validators_list.sv_list:
                logger.warning('Stake selector not in stake_list for this epoch..')
                return False

            if not stake_validators_list.validate_hash(b.reveal_hash,
                                                       b.blocknumber,
                                                       config.dev.hashchain_nums-1,
                                                       self.transactions[0].txto):
                logger.warning('Supplied hash does not iterate to terminator: failed validation')
                return False

            target_chain = select_target_hashchain(b.prev_blockheaderhash)

            if not stake_validators_list.validate_hash(b.vote_hash,
                                                       b.blocknumber,
                                                       target_chain,
                                                       self.transactions[0].txto):
                logger.warning('Not all the reveal_hashes are valid..')
                return False


        if not self._validate_tx_in_block(chain):
            logger.warning('Block validate_tx_in_block error: failed validation')
            return False

        return True

    def validate_block_timestamp(self, last_block_timestamp):
        # TODO: Add minimum minting delay
        if last_block_timestamp >= self.blockheader.timestamp:
            return False
        curr_time = ntp.getTime()
        if curr_time == 0:
            return False

        max_block_number = int((curr_time - last_block_timestamp) / config.dev.block_creation_seconds)
        if self.blockheader.blocknumber > max_block_number:
            return False
