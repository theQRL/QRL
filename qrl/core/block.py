# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.Transaction_subtypes import TX_SUBTYPE_STAKE, TX_SUBTYPE_COINBASE, TX_SUBTYPE_TX
from qrl.core import logger
from qrl.core.blockheader import BlockHeader
from qrl.core.Transaction import Transaction, CoinBase
from qrl.crypto.misc import sha256, merkle_tx_hash
from qrl.generated import qrl_pb2


class Block(object):
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.Block()
        else:
            self.blockheader = BlockHeader(protobuf_block.header)

    @property
    def transactions(self):
        return self._data.transactions

    @property
    def duplicate_transactions(self):
        return self._data.dup_transactions

    @property
    def state(self):
        return self._data.state

    @property
    def stake_list(self):
        return self._data.stake_list

    def create(self, chain, reveal_hash, last_block_number=-1):
        if last_block_number == -1:
            data = chain.block_chain_buffer.get_last_block()  # m_get_last_block()
        else:
            data = chain.block_chain_buffer.get_block_n(last_block_number)

        last_block_number = data.blockheader.blocknumber
        prev_blockheaderhash = data.blockheader.headerhash

        hashedtransactions = []

        self._data.transactions.extend([qrl_pb2.Transaction()])
        fee_reward = 0

        for tx in chain.transaction_pool:
            if tx.subtype == TX_SUBTYPE_TX:
                fee_reward += tx.fee
            hashedtransactions.append(tx.txhash)
            self._data.transactions.extend([tx.pbdata])  # copy memory rather than sym link

        for tx in chain.duplicate_tx_pool:
            self._data.duplicate_transactions.extend([chain.duplicate_tx_pool[tx].pbdata])

        if not hashedtransactions:
            hashedtransactions = [sha256('')]

        hashedtransactions = merkle_tx_hash(hashedtransactions)

        self.blockheader = BlockHeader().create(chain=chain,
                                                blocknumber=last_block_number + 1,
                                                reveal_hash=reveal_hash,
                                                prev_blockheaderhash=prev_blockheaderhash,
                                                hashedtransactions=hashedtransactions,
                                                fee_reward=fee_reward)

        self._data.header.MergeFrom(self.blockheader._data)


        signing_xmss = chain.block_chain_buffer.get_slave_xmss(last_block_number + 1)

        coinbase_tx = CoinBase.create(self.blockheader, signing_xmss)

        sv_list = chain.block_chain_buffer.get_stake_validators_list(last_block_number + 1).sv_list
        coinbase_tx.pbdata.nonce = sv_list[chain.mining_address].nonce + 1

        coinbase_tx.sign(signing_xmss)  # Sign after nonce has been set

        self._data.transactions[0].CopyFrom(coinbase_tx.pbdata)

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

            coinbase_tx = CoinBase(self.transactions[0])

            if coinbase_tx.subtype != TX_SUBTYPE_COINBASE:
                logger.warning('BLOCK : First txn must be a COINBASE txn')
                return False

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

            if blk_header.blocknumber == 1:
                found = False
                for protobuf_tx in self.transactions:
                    tx = Transaction.from_pbdata(protobuf_tx)
                    if tx.subtype == TX_SUBTYPE_STAKE:
                        if tx.txfrom == blk_header.stake_selector:
                            found = True
                            reveal_hash = chain.select_hashchain(coinbase_tx.txto,
                                                                 tx.hash, blocknumber=1)

                            if sha256(bin2hstr(tuple(blk_header.reveal_hash)).encode()) != reveal_hash:
                                logger.warning('reveal_hash does not hash correctly to terminator: failed validation')
                                return False

                if not found:
                    logger.warning('Stake selector not in block.stake: failed validation')
                    return False

            else:  # we look in stake_list for the hash terminator and hash to it..
                stake_validators_list = chain.block_chain_buffer.get_stake_validators_list(self.blockheader.blocknumber)
                if coinbase_tx.txto not in stake_validators_list.sv_list:
                    logger.warning('Stake selector not in stake_list for this epoch..')
                    return False

                if not stake_validators_list.validate_hash(blk_header.reveal_hash,
                                                           blk_header.blocknumber,
                                                           coinbase_tx.txto):
                    logger.warning('Supplied hash does not iterate to terminator: failed validation')
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
        coinbase_txn = CoinBase(self.transactions[0])

        sv_list = chain.block_chain_buffer.stake_list_get(self.blockheader.blocknumber)
        valid = coinbase_txn.validate_extended(sv_list=sv_list, blockheader=self.blockheader)

        if not valid:
            logger.warning('coinbase txn in block failed')
            return False

        for tx_num in range(1, len(self.transactions)):
            protobuf_tx = self.transactions[tx_num]
            tx = Transaction.from_pbdata(protobuf_tx)
            if not tx.validate():
                logger.warning('invalid tx in block')
                return False

        for protobuf_tx in self.duplicate_transactions:
            tx = Transaction.from_pbdata(protobuf_tx)
            if not tx.validate():
                logger.warning('invalid duplicate tx in block')
                return False

        return True

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Block()
        Parse(json_data, pbdata)
        return Block(pbdata)

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)