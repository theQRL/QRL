# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from abc import ABCMeta, abstractmethod

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256, getAddress, bin2hstr, str2bin

from qrl.core import helper, config, logger
from qrl.core.Transaction_subtypes import *
from qrl.crypto.hashchain import hashchain_reveal
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2


class Transaction(object, metaclass=ABCMeta):
    """
    Abstract Base class to be derived by all other transactions
    """

    def __init__(self, protobuf_transaction=None):
        self._data = protobuf_transaction  # This object cointains persistable data
        if protobuf_transaction is None:
            self._data = qrl_pb2.Transaction()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf Transaction object
        :rtype: qrl_pb2.Transaction
        """
        return self._data

    @property
    def subtype(self):
        return self._data.type

    @property
    def nonce(self):
        return self._data.nonce

    @property
    def txfrom(self):
        return self._data.addr_from

    @property
    def pubhash(self):
        # FIXME: Review this. Leon?
        return bytes(sha256(bytes(self.PK) + str(self.ots_key).encode()))

    @property
    def txhash(self):
        return self._data.transaction_hash

    @property
    def ots_key(self):
        return self._data.ots_key

    @property
    def PK(self):
        return self._data.public_key

    @property
    def signature(self):
        return self._data.signature

    @staticmethod
    def tx_id_to_name(id):
        # FIXME: Move to enums
        id_name = {
            qrl_pb2.Transaction.TRANSFER: 'TX',
            qrl_pb2.Transaction.STAKE: 'STAKE',
            qrl_pb2.Transaction.COINBASE: 'COINBASE',
            qrl_pb2.Transaction.LATTICE: 'LATTICE',
            qrl_pb2.Transaction.DUPLICATE: 'DUPLICATE'
        }
        return id_name[id]

    @staticmethod
    def from_pbdata(pbdata: qrl_pb2.Transaction):
        txtype = TYPEMAP[pbdata.type]
        return txtype(pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Transaction()
        Parse(json_data, pbdata)
        return Transaction.from_pbdata(pbdata)

    @abstractmethod
    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        return bytes()

    def calculate_txhash(self):
        return bytes(sha2_256(self._get_hashable_bytes() + self.pubhash))

    def sign(self, xmss):
        self._data.signature = xmss.SIGN(self.txhash)

    def _validate_signed_hash(self, height=config.dev.xmss_tree_height):
        if self.subtype != TX_SUBTYPE_COINBASE and getAddress('Q', self.PK) != self.txfrom.decode():
            logger.warning('Public key verification failed')
            return False

        if not XMSS.VERIFY(message=self.txhash,
                           signature=self.signature,
                           pk=self.PK,
                           height=height):
            logger.warning('xmss_verify failed')
            return False

        return True

    def _validate_subtype(self, subtype, expected_subtype):
        if subtype != expected_subtype:
            logger.warning('Invalid subtype')
            logger.warning('Found: %s Expected: %s', subtype, expected_subtype)
            return False

        return True

    def get_message_hash(self):
        # FIXME: refactor, review that things are not recalculated too often, cache, etc.
        return self.calculate_txhash()

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)


class SimpleTransaction(Transaction):
    """
    SimpleTransaction for the transaction of QRL from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(SimpleTransaction, self).__init__(protobuf_transaction)
        self._data.type = qrl_pb2.Transaction.TRANSFER

    @property
    def txto(self):
        return self._data.transfer.addr_to

    @property
    def amount(self):
        return self._data.transfer.amount

    @property
    def fee(self):
        return self._data.transfer.fee

    def pre_condition(self, tx_state):
        # if state.uptodate() is False:
        #	logger.info(( 'Warning state not updated to allow safe tx validation, tx validity could be unreliable..'))
        #	return False
        tx_balance = tx_state[1]

        if self.amount < 0:
            # FIXME: logging txhash here is not useful as this changes when signing
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.amount:
            # FIXME: logging txhash here is not useful as this changes when signing
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.amount)
            return False

        return True

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        tmptxhash = self.txfrom + \
                    self.txto + \
                    str(self.amount).encode() + \
                    str(self.fee).encode()
        return bytes(sha256(tmptxhash))

    @staticmethod
    def create(addr_from, addr_to, amount, fee, xmss_pk, xmss_ots_index):
        transaction = SimpleTransaction()

        transaction._data.addr_from = bytes(addr_from.encode())
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer.addr_to = bytes(addr_to.encode())
        transaction._data.transfer.amount = int(amount)     # FIXME: Review conversions for quantities
        transaction._data.transfer.fee = int(fee)           # FIXME: Review conversions for quantities

        transaction._data.ots_key = xmss_ots_index
        transaction._data.transaction_hash = transaction.calculate_txhash()

        return transaction

    def validate_tx(self):
        if self.subtype != TX_SUBTYPE_TX:
            return False

        # FIXME: what does this comment means?
        # sanity check: this is not how the economy is supposed to work!
        if self.amount <= 0:
            logger.info('State validation failed for %s because negative or zero', self.txhash)
            logger.info('Amount %d', self.amount)
            return False

        # cryptographic checks
        if self.txhash != self.calculate_txhash():
            return False

        if not self._validate_signed_hash():
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def state_validate_tx(self, tx_state, transaction_pool):

        if not self.pre_condition(tx_state):
            return False

        pubhash = self.pubhash

        tx_pubhashes = tx_state[2]

        if pubhash in tx_pubhashes:
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.pubhash == pubhash:
                logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
                return False

        return True


class StakeTransaction(Transaction):
    """
    StakeTransaction performed by the nodes who would like
    to stake.
    """

    def __init__(self, protobuf_transaction=None):
        super(StakeTransaction, self).__init__(protobuf_transaction)
        self._data.type = qrl_pb2.Transaction.STAKE

    @property
    def balance(self):
        return self._data.stake.balance

    @property
    def epoch(self):
        return self._data.stake.epoch

    @property
    def finalized_blocknumber(self):
        return self._data.stake.finalized_blocknumber

    @property
    def finalized_headerhash(self):
        return self._data.stake.finalized_headerhash

    @property
    def slave_public_key(self):
        return self._data.stake.slavePK

    @property
    def hash(self):
        return self._data.stake.hash

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        tmptxhash = ''.join([bin2hstr(b) for b in self.hash])
        tmptxhash = str2bin(tmptxhash
                            + bin2hstr(self.slave_public_key)
                            + bin2hstr(sha2_256(bytes(self.epoch)))
                            + bin2hstr(sha2_256(bytes(self.subtype)))
                            + bin2hstr(sha2_256(bytes(self.finalized_blocknumber)))
                            + bin2hstr(self.finalized_headerhash))
        return bytes(tmptxhash)

    @staticmethod
    def create(blocknumber,
               xmss,
               slavePK,
               finalized_blocknumber,
               finalized_headerhash,
               hashchain_terminator=None,
               balance=None):
        """
        >>> s = StakeTransaction()
        >>> slave = XMSS(4)
        >>> isinstance(s.create(0, XMSS(4), slave.pk(), 0, bytes((0, 1)), None, 10), StakeTransaction)
        True
        """
        if not balance:
            logger.info('Invalid Balance %d', balance)
            raise Exception

        transaction = StakeTransaction()

        transaction._data.addr_from = bytes(xmss.get_address().encode())
        transaction._data.public_key = bytes(xmss.pk())

        # Stake specific
        transaction._data.stake.balance = balance
        transaction._data.stake.epoch = blocknumber // config.dev.blocks_per_epoch  # in this block the epoch is..
        transaction._data.stake.finalized_blocknumber = finalized_blocknumber
        transaction._data.stake.finalized_headerhash = bytes(finalized_headerhash)
        transaction._data.stake.slavePK = bytes(slavePK)

        if hashchain_terminator is None:
            transaction._data.stake.hash[:] = hashchain_reveal(xmss.get_seed_private(), epoch=transaction.epoch + 1)
        else:
            transaction._data.stake.hash[:] = hashchain_terminator

        # WARNING: These fields need to the calculated once all other fields are set
        transaction._data.ots_key = xmss.get_index()
        transaction._data.transaction_hash = transaction.calculate_txhash()
        return transaction

    def validate_tx(self):
        # FIX: Directly combine all this
        txhash = self.calculate_txhash()

        if txhash != self.txhash:
            logger.info('Invalid Transaction hash')
            return False

        if not self._validate_subtype(self.subtype, TX_SUBTYPE_STAKE):
            return False

        if not helper.isValidAddress(self.txfrom):
            logger.info('Invalid From Address %s', self.txfrom)
            return False

        if not self._validate_signed_hash():
            return False

        return True

    def state_validate_tx(self, tx_state):
        if self.subtype != TX_SUBTYPE_STAKE:
            return False

        state_balance = tx_state[1]
        state_pubhashes = tx_state[2]

        if self.balance > state_balance:
            logger.info('Stake Transaction Balance exceeds maximum balance')
            logger.info('Max Balance Expected %d', state_balance)
            logger.info('Balance found %d', self.balance)
            return False

        # TODO no need to transmit pubhash over the network
        # pubhash has to be calculated by the receiver
        if self.pubhash in state_pubhashes:
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.hash)
            return False

        return True


class CoinBase(Transaction):
    """
    CoinBase is the type of transaction to credit the block_reward to
    the stake selector who created the block.
    """

    def __init__(self, protobuf_transaction=None):
        super(CoinBase, self).__init__(protobuf_transaction)
        self._data.type = qrl_pb2.Transaction.COINBASE

        # This attribute is not persistable
        self.blockheader = None

    @property
    def txto(self):
        return self._data.coinbase.addr_to

    @property
    def amount(self):
        return self._data.coinbase.amount

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        tmptxhash = bytes(self.blockheader.prev_blockheaderhash) + \
                    bytes(str(self.blockheader.blocknumber).encode()) + \
                    bytes(self.blockheader.headerhash)
        return bytes(sha256(tmptxhash))

    @staticmethod
    def create(blockheader, xmss):
        transaction = CoinBase()
        transaction.blockheader = blockheader

        transaction._data.addr_from = bytes(blockheader.stake_selector.encode())
        transaction._data.public_key = bytes(xmss.pk())

        transaction._data.coinbase.addr_to = bytes(blockheader.stake_selector.encode())
        transaction._data.coinbase.amount = blockheader.block_reward + blockheader.fee_reward

        transaction._data.ots_key = xmss.get_index()
        transaction._data.transaction_hash = transaction.calculate_txhash()

        return transaction

    def validate_tx(self, chain, blockheader):
        sv_list = chain.block_chain_buffer.stake_list_get(blockheader.blocknumber)
        if blockheader.blocknumber > 1 and sv_list[self.txto].slave_public_key != self.PK:
            logger.warning('Stake validator doesnt own the Public key')
            logger.warning('Expected public key %s', sv_list[self.txto].slave_public_key)
            logger.warning('Found public key %s', self.PK)
            return False

        self.blockheader = blockheader

        if self.txto != self.txfrom:
            logger.warning('Non matching txto and txfrom')
            logger.warning('txto: %s txfrom: %s', self.txto, self.txfrom)
            return False

        tmp_txhash = self.calculate_txhash()
        if self.txhash != self.calculate_txhash():
            logger.warning('Block_headerhash doesnt match')
            logger.warning('Found: %s', self.txhash)
            logger.warning('Expected: %s', tmp_txhash)
            return False

        # Slave XMSS is used to sign COINBASE txn having quite low XMSS height
        if not self._validate_signed_hash(height=config.dev.slave_xmss_height):
            return False

        return True


class LatticePublicKey(Transaction):
    """
    LatticePublicKey transaction to store the public key.
    This transaction has been designed for Ephemeral Messaging.
    """

    def __init__(self, protobuf_transaction=None):
        super(LatticePublicKey, self).__init__(protobuf_transaction)
        self._data.type = qrl_pb2.Transaction.LATTICE
        self._data.pk_kyber = None
        self._data.pk_tesla = None

    @property
    def kyber_pk(self):
        return self._data.pk_kyber

    @property
    def tesla_pk(self):
        return self._data.pk_tesla

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        tmptxhash = self.kyber_pk + self.tesla_pk
        return bytes(sha256(tmptxhash))

    @staticmethod
    def create(xmss, kyber_pk, tesla_pk):
        transaction = LatticePublicKey()

        transaction._data.txfrom = xmss.get_address()
        transaction._data.public_key = xmss.pk()

        transaction._data.latticePK.kyber_pk = kyber_pk
        transaction._data.latticePK.tesla_pk = tesla_pk

        transaction._data.ots_key = xmss.get_index()
        transaction._data.transaction_hash = transaction.calculate_txhash()

        return transaction

    def validate_tx(self):
        if not self._validate_subtype(self.subtype, TX_SUBTYPE_LATTICE):
            return False

        txhash = self.calculate_txhash()
        if self.txhash != txhash:
            logger.info('Invalid Txhash')
            logger.warning('Found: %s Expected: %s', self.txhash, txhash)
            return False

        if not self._validate_signed_hash():
            return False

        return True


class DuplicateTransaction(Transaction):
    def __init__(self, protobuf_transaction=None):
        super(DuplicateTransaction, self).__init__(protobuf_transaction)
        self._data.type = qrl_pb2.Transaction.DUPLICATE

        self._data.duplicate.block_number = 0
        self._data.duplicate.hash_header_prev = None

        self._data.duplicate.coinbase1 = None
        self._data.duplicate.coinbase1_hhash = None

        self._data.duplicate.coinbase2 = None
        self._data.duplicate.coinbase2_hhash = None

        # TODO: review, this is not persistable
        self.headerhash = None
        self.coinbase = None

    @property
    def blocknumber(self):
        return self._data.duplicate.blocknumber

    @property
    def prev_header_hash(self):
        return self._data.duplicate.prev_header_hash

    @property
    def headerhash1(self):
        return self._data.duplicate.coinbase1_hhash

    @property
    def headerhash2(self):
        return self._data.duplicate.coinbase2_hhash

    @property
    def coinbase1(self):
        return self._data.duplicate.coinbase1

    @property
    def coinbase2(self):
        return self._data.duplicate.coinbase2

    # def get_message_hash(self):
    #     return self.headerhash1 + self.headerhash2

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        # TODO: Review get_message_hash is too different/inconsistent
        tmptxhash = bytes(self.prev_blockheaderhash) + \
                    bytes(str(self.blocknumber).encode()) + \
                    bytes(self.headerhash) + \
                    bytes(self.coinbase.pubhash)
        # FIXME: Review. coinbase2?

        return bytes(sha256(tmptxhash))

    @staticmethod
    def create(block1, block2):
        transaction = DuplicateTransaction()

        transaction._data.duplicate.blocknumber = block1.blockheader.blocknumber
        transaction._data.duplicate.prev_header_hash = block1.blockheader.prev_blockheaderhash

        transaction._data.duplicate.coinbase1 = block1.transactions[0]
        transaction._data.duplicate.coinbase1_hhash = block1.blockheader.headerhash
        transaction._data.duplicate.coinbase2 = block2.transactions[0]
        transaction._data.duplicate.coinbase2_hhash = block2.blockheader.headerhash

        # FIXME: No hashing? This seems wrong

        return transaction

    def validate_tx(self):
        if self.headerhash1 == self.headerhash2 and self.coinbase1.signature == self.coinbase2.signature:
            logger.info('Invalid DT txn')
            logger.info('coinbase1 and coinbase2 txn are same')
            return False

        if not self.validate_hash(self.headerhash1, self.coinbase1):
            return False

        if not self.validate_hash(self.headerhash2, self.coinbase2):
            return False

        return True

    def validate_hash(self, headerhash, coinbase):
        self.headerhash = headerhash
        self.coinbase = coinbase

        txhash = self.calculate_txhash()

        if coinbase.txhash != txhash:
            logger.info('Invalid Txhash')
            logger.warning('Found: %s Expected: %s', coinbase.txhash, txhash)
            return False

        if not coinbase._validate_signed_hash(height=config.dev.slave_xmss_height):
            return False

        return True

    # def from_txdict(self, dict_tx):
    #     # FIXME: Remove once we move completely to protobuf
    #     return self.from_dict(dict_tx)
    #
    # # def from_dict(self, dict_tx):
    # #     # FIXME: Remove once we move completely to protobuf
    # #     self.blocknumber = dict_tx['blocknumber']
    # #     self.prev_blockheaderhash = bytes(dict_tx['prev_blockheaderhash'])
    # #
    # #     self._data.duplicate.coinbase1 = CoinBase().from_dict(dict_tx['coinbase1'])
    # #     self._data.duplicate.coinbase1_hhash = bytes(dict_tx['headerhash1'])
    # #
    # #     self._data.duplicate.coinbase2 = CoinBase().from_dict(dict_tx['coinbase2'])
    # #     self._data.duplicate.coinbase2_hhash = bytes(dict_tx['headerhash2'])
    # #
    # #     return self


TYPEMAP = {
    qrl_pb2.Transaction.TRANSFER: SimpleTransaction,
    qrl_pb2.Transaction.STAKE: StakeTransaction,
    qrl_pb2.Transaction.COINBASE: CoinBase,
    qrl_pb2.Transaction.LATTICE: LatticePublicKey,
    qrl_pb2.Transaction.DUPLICATE: DuplicateTransaction
}
