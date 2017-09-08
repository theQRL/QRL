# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import simplejson as json

from qrl.core import transaction, logger, config, ntp
from qrl.core.blockheader import BlockHeader
from qrl.core.helper import select_target_hashchain
from qrl.core.transaction import Transaction
from qrl.crypto.misc import sha256, merkle_tx_hash


class Block(object):
    @staticmethod
    def isHashPresent(txhash, buffer, blocknumber):
        if not buffer:
            return False

        min_blocknum = min(buffer)
        max_blocknum = min(blocknumber - 1, max(buffer))

        for blocknum in range(min_blocknum, max_blocknum + 1):
            if txhash in buffer[blocknum]:
                return True

        return False

    def create(self, chain, hashchain_link, reveal_list=None, vote_hashes=None, last_block_number=-1):
        # FIXME: probably this should turn into a constructor
        if not reveal_list:
            reveal_list = []
        if not vote_hashes:
            vote_hashes = []

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
            if tx.subtype == transaction.TX_SUBTYPE_TX:
                fee_reward += tx.fee
            hashedtransactions.append(tx.txhash)
            self.transactions.append(tx)  # copy memory rather than sym link

        if not hashedtransactions:
            hashedtransactions = sha256('')

        hashedtransactions = merkle_tx_hash(hashedtransactions)

        self.blockheader = BlockHeader()
        self.blockheader.create(chain=chain,
                                blocknumber=last_block_number + 1,
                                reveal_list=reveal_list,
                                vote_hashes=vote_hashes,
                                hashchain_link=hashchain_link,
                                prev_blockheaderhash=prev_blockheaderhash,
                                hashedtransactions=hashedtransactions,
                                fee_reward=fee_reward)

        coinbase_tx = transaction.CoinBase().create(self.blockheader.block_reward, self.blockheader.headerhash,
                                                    chain.my[0][1])
        self.transactions[0] = coinbase_tx
        coinbase_tx.nonce = chain.block_chain_buffer.get_stxn_state(last_block_number + 1, chain.mining_address)[0] + 1

    def json_to_block(self, json_block):
        self.blockheader = BlockHeader()
        self.blockheader.json_to_blockheader(json_block['blockheader'])

        transactions = json_block['transactions']
        self.transactions = []
        for tx in transactions:
            self.transactions.append(Transaction.get_tx_obj(tx))

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

    def validate_tx_in_block(self):
        # Validating coinbase txn
        coinbase_txn = self.transactions[0]
        valid = coinbase_txn.validate_tx(block_headerhash=self.blockheader.headerhash)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_num in range(1, len(self.transactions)):
            tx = self.transactions[tx_num]
            if tx.validate_tx() is False:
                logger.warning('invalid tx in block')
                logger.warning('subtype: %s txhash: %s txfrom: %s', tx.subtype, tx.txhash, tx.txfrom)
                return False

        return True

    def validate_block(self, chain, verify_block_reveal_list=True):  # check validity of new block..
        """
        block validation
        :param chain:
        :param verify_block_reveal_list:
        :return:
        """
        b = self.blockheader
        last_blocknum = b.blocknumber - 1

        if len(self.transactions) == 0:
            logger.warning('BLOCK : There must be atleast 1 txn')
            return False

        coinbase_tx = self.transactions[0]

        try:
            if coinbase_tx.subtype != transaction.TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False
        except Exception as e:
            logger.exception(e)
            return False

        if coinbase_tx.txfrom != self.blockheader.stake_selector:
            logger.info('Non matching txto and stake_selector')
            logger.info('txto: %s stake_selector %s', coinbase_tx.txfrom, self.blockheader.stake_selector)
            return False

        if coinbase_tx.amount != self.blockheader.block_reward:
            logger.info('Block_reward doesnt match')
            logger.info('Found: %d Expected: %d', coinbase_tx.amount, self.blockheader.block_reward)
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
                if tx.subtype == transaction.TX_SUBTYPE_STAKE:
                    if tx.txfrom == b.stake_selector:
                        x = 1
                        hash, _ = chain.select_hashchain(chain.m_blockchain[-1].blockheader.headerhash,
                                                         b.stake_selector,
                                                         tx.hash, blocknumber=1)

                        if sha256(b.hash) != hash or hash not in tx.hash:
                            logger.warning('Hashchain_link does not hash correctly to terminator: failed validation')
                            return False
            if x != 1:
                logger.warning('Stake selector not in block.stake: failed validation')
                return False
        else:  # we look in stake_list for the hash terminator and hash to it..
            if b.stake_selector not in chain.state.stake_validators_list.sv_list:
                logger.warning('Stake selector not in stake_list for this epoch..')
                return False

            if not chain.state.stake_validators_list.validate_hash(b.hash,
                                                                   b.blocknumber,
                                                                   config.dev.hashchain_nums-1,
                                                                   b.stake_selector):
                logger.warning('Supplied hash does not iterate to terminator: failed validation')
                return False

            if len(b.reveal_list) != len(set(b.reveal_list)):
                logger.warning('Repetition in reveal_list')
                return False

            if verify_block_reveal_list:
                i = 0
                for r in b.reveal_list:
                    if not chain.state.stake_validators_list.validate_hash(r,
                                                                           self.blockheader.blocknumber,
                                                                           config.dev.hashchain_nums - 1):
                        logger.warning('Not all the reveal_hashes are valid..')
                        return False

                i = 0
                target_chain = select_target_hashchain(b.prev_blockheaderhash)
                for r in b.vote_hashes:
                    if not chain.state.stake_validators_list.validate_hash(r,
                                                                           b.blocknumber,
                                                                           target_chain):
                        logger.warning('Not all the reveal_hashes are valid..')
                        return False

        if b.generate_headerhash() != b.headerhash:
            logger.warning('Headerhash false for block: failed validation')
            return False

        tmp_last_block = chain.block_chain_buffer.get_block_n(last_blocknum)

        if tmp_last_block.blockheader.headerhash != b.prev_blockheaderhash:
            logger.warning('Headerhash not in sequence: failed validation')
            return False

        if tmp_last_block.blockheader.blocknumber != b.blocknumber - 1:
            logger.warning('Block numbers out of sequence: failed validation')
            return False

        if not self.validate_tx_in_block():
            logger.warning('Block validate_tx_in_block error: failed validation')
            return False

        if len(self.transactions) == 1:
            txhashes = sha256('')
        else:
            txhashes = []
            for tx_num in range(1, len(self.transactions)):
                tx = self.transactions[tx_num]
                txhashes.append(tx.txhash)

        if merkle_tx_hash(txhashes) != b.tx_merkle_root:
            logger.warning('Block hashedtransactions error: failed validation')
            return False

        return True

    def validate_block_timestamp(self, last_block_timestamp):
        if last_block_timestamp >= self.blockheader.timestamp:
            return False
        curr_time = ntp.getTime()
        if curr_time == 0:
            return False

        max_block_number = int((curr_time - last_block_timestamp) / config.dev.block_creation_seconds)
        if self.blockheader.blocknumber > max_block_number:
            return False
