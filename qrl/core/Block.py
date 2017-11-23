# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import OrderedDict

from google.protobuf.json_format import MessageToJson, Parse

from qrl.core import config
from qrl.core.Transaction import CoinBase, Transaction
from qrl.core.BlockHeader import BlockHeader
from qrl.core.VoteMetadata import VoteMetadata
from qrl.crypto.misc import sha256, merkle_tx_hash
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2


class Block(object):
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.Block()

        self.blockheader = BlockHeader(self._data.header)

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
    def epoch(self):
        return int(self.block_number // config.dev.blocks_per_epoch)

    @property
    def headerhash(self):
        return self.blockheader.headerhash

    @property
    def prev_headerhash(self):
        return self.blockheader.prev_blockheaderhash

    @property
    def vote(self):
        return self._data.vote

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

    @property
    def stake_selector(self):
        return self.blockheader.stake_selector

    @property
    def reveal_hash(self):
        return self.blockheader.reveal_hash

    @property
    def block_reward(self):
        return self.blockheader.block_reward

    @property
    def timestamp(self):
        return self.blockheader.timestamp

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Block()
        Parse(json_data, pbdata)
        return Block(pbdata)

    def to_json(self)->str:
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)

    @staticmethod
    def create(staking_address: bytes,
               block_number: int,
               reveal_hash: bytes,
               prevblock_headerhash: bytes,
               transactions: list,
               duplicate_transactions: OrderedDict,
               vote: VoteMetadata,
               signing_xmss: XMSS,
               nonce: int):

        block = Block()
        block._data.transactions.extend([qrl_pb2.Transaction()])  # FIXME: Empty for coinbase?

        # Process transactions
        hashedtransactions = []
        fee_reward = 0

        for tx in transactions:
            if tx.subtype == qrl_pb2.Transaction.TRANSFER:
                fee_reward += tx.fee
            hashedtransactions.append(tx.txhash)
            block._data.transactions.extend([tx.pbdata])  # copy memory rather than sym link

        if not hashedtransactions:
            hashedtransactions = [sha256(b'')]

        txs_hash = merkle_tx_hash(hashedtransactions)           # FIXME: Find a better name, type changes

        for tx in duplicate_transactions.values():  # TODO: Add merkle hash for dup txn
            block._data.duplicate_transactions.extend([tx.pbdata])

        for staker in vote.stake_validator_vote:  # TODO: Add merkle hash for vote
            block._data.vote.extend([vote.stake_validator_vote[staker].pbdata])

        tmp_blockheader = BlockHeader.create(staking_address=staking_address,
                                             blocknumber=block_number,
                                             reveal_hash=reveal_hash,
                                             prev_blockheaderhash=prevblock_headerhash,
                                             hashedtransactions=txs_hash,
                                             fee_reward=fee_reward)

        block._data.header.MergeFrom(tmp_blockheader.pbdata)

        # Prepare coinbase tx
        coinbase_tx = CoinBase.create(tmp_blockheader, signing_xmss)
        coinbase_tx.pbdata.nonce = nonce
        coinbase_tx.sign(signing_xmss)  # Sign after nonce has been set

        # Replace first tx
        block._data.transactions[0].CopyFrom(coinbase_tx.pbdata)

        return block

    def add_transaction(self, tx: Transaction):
        # TODO: Verify something basic here?
        self._data.transactions.extend(tx.pbdata)
