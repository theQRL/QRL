# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from abc import ABCMeta, abstractmethod

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import sha2_256, getAddress, bin2hstr, str2bin

from qrl.core import config, logger
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
    def tx_id_to_name(idarg):
        # FIXME: Move to enums
        id_name = {
            qrl_pb2.Transaction.TRANSFER: 'TX',
            qrl_pb2.Transaction.STAKE: 'STAKE',
            qrl_pb2.Transaction.DESTAKE: 'DESTAKE',
            qrl_pb2.Transaction.COINBASE: 'COINBASE',
            qrl_pb2.Transaction.LATTICE: 'LATTICE',
            qrl_pb2.Transaction.DUPLICATE: 'DUPLICATE'
        }
        return id_name[idarg]

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

    @abstractmethod
    def _validate_custom(self)->bool:
        """
        This is an extension point for derived classes validation
        If derived classes need additional field validation they should override this member
        """
        return True

    def validate(self)->bool:
        """
        This method calls validate_or_raise, logs any failure and returns True or False accordingly
        The main purpose is to avoid exceptions and accomodate legacy code
        :return: True is the transation is valid
        :rtype: bool
        """
        try:
            self.validate_or_raise()
        except ValueError as e:
            logger.info('[%s] failed validate_tx', bin2hstr(self.txhash))
            logger.warning(str(e))
            return False
        except Exception as e:
            logger.exception(e)
            return False
        return True

    def validate_or_raise(self)->bool:
        """
        This method will validate a transaction and raise exception if problems are found
        :return: True if the exception is valid, exceptions otherwise
        :rtype: bool
        """
        if not isinstance(self, TYPEMAP[self.subtype]):
            raise TypeError('Invalid subtype: Found: %s Expected: %s', type(self), TYPEMAP[self.subtype])

        if not self._validate_custom():
            raise ValueError("Custom validation failed")

        # cryptographic checks
        if self.txhash != self.calculate_txhash():
            raise ValueError("Invalid transaction hash")

        # FIXME: Why is coinbase skipped?
        if not isinstance(self, CoinBase) and getAddress('Q', self.PK) != self.txfrom.decode():
            raise ValueError('Public key and address dont match')

        if not XMSS.VERIFY(message=self.txhash,
                           signature=self.signature,
                           pk=self.PK):
            raise ValueError("Invalid xmss signature")

        return True

    def get_message_hash(self):
        # FIXME: refactor, review that things are not recalculated too often, cache, etc.
        return self.calculate_txhash()

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)


class TransferTransaction(Transaction):
    """
    SimpleTransaction for the transaction of QRL from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(TransferTransaction, self).__init__(protobuf_transaction)
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
    def create(addr_from: bytes, addr_to: bytes, amount, fee, xmss_pk, xmss_ots_index):
        transaction = TransferTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer.addr_to = addr_to
        transaction._data.transfer.amount = int(amount)  # FIXME: Review conversions for quantities
        transaction._data.transfer.fee = int(fee)  # FIXME: Review conversions for quantities

        transaction._data.ots_key = xmss_ots_index
        transaction._data.transaction_hash = transaction.calculate_txhash()

        return transaction

    def _validate_custom(self):
        if self.amount <= 0:
            raise ValueError('[%s] Invalid amount = %d', bin2hstr(self.txhash), self.amount)
        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, tx_state, transaction_pool):
        # FIXME: This makes sense and should be enabled back
        # if not state.uptodate():
        #	logger.info(( 'Warning state not updated to allow safe tx validation, tx validity could be unreliable..'))
        #	return False

        tx_balance = tx_state[1]
        tx_pubhashes = tx_state[2]

        if self.amount < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.amount:
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.amount)
            return False

        if self.pubhash in tx_pubhashes:
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.pubhash == self.pubhash:
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
    def activation_blocknumber(self):
        return self._data.stake.activation_blocknumber

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
        tmptxhash = bin2hstr(tuple(self.hash))
        tmptxhash = str2bin(tmptxhash
                            + bin2hstr(self.slave_public_key)
                            + bin2hstr(sha2_256(bytes(self.activation_blocknumber)))
                            + bin2hstr(sha2_256(bytes(self.subtype)))
                            + bin2hstr(sha2_256(bytes(self.finalized_blocknumber)))
                            + bin2hstr(self.finalized_headerhash))
        return bytes(tmptxhash)

    @staticmethod
    def create(activation_blocknumber,
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
        transaction._data.stake.activation_blocknumber = activation_blocknumber
        transaction._data.stake.finalized_blocknumber = finalized_blocknumber
        transaction._data.stake.finalized_headerhash = bytes(finalized_headerhash)
        transaction._data.stake.slavePK = bytes(slavePK)

        if hashchain_terminator is None:
            epoch = activation_blocknumber // config.dev.blocks_per_epoch
            transaction._data.stake.hash = hashchain_reveal(xmss.get_seed_private(), epoch=epoch)
        else:
            transaction._data.stake.hash = hashchain_terminator

        # WARNING: These fields need to the calculated once all other fields are set
        transaction._data.ots_key = xmss.get_index()
        transaction._data.transaction_hash = transaction.calculate_txhash()
        return transaction

    def _validate_custom(self):
        return True

    def validate_extended(self, tx_state):
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


class DestakeTransaction(Transaction):
    """
    DestakeTransaction performed by the nodes who would not like
    to stake.
    """

    def __init__(self, protobuf_transaction=None):
        super(DestakeTransaction, self).__init__(protobuf_transaction)
        self._data.type = qrl_pb2.Transaction.DESTAKE

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        tmptxhash = str2bin(bin2hstr(sha2_256(bytes(self.subtype))))
        return bytes(tmptxhash)

    @staticmethod
    def create(xmss):
        """
        >>> s = DestakeTransaction()
        >>> isinstance(s.create(XMSS(4)), DestakeTransaction)
        True
        """

        transaction = DestakeTransaction()

        transaction._data.addr_from = bytes(xmss.get_address().encode())
        transaction._data.public_key = bytes(xmss.pk())

        # WARNING: These fields need to the calculated once all other fields are set
        transaction._data.ots_key = xmss.get_index()
        transaction._data.transaction_hash = transaction.calculate_txhash()
        return transaction

    def _validate_custom(self):
        return True

    def validate_extended(self, tx_state):
        state_pubhashes = tx_state[2]

        if self.pubhash in state_pubhashes:
            logger.info('State validation failed for %s because: OTS Public key re-use detected')
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

        transaction._data.addr_from = blockheader.stake_selector
        transaction._data.public_key = bytes(xmss.pk())

        transaction._data.coinbase.addr_to = blockheader.stake_selector
        transaction._data.coinbase.amount = blockheader.block_reward + blockheader.fee_reward

        transaction._data.ots_key = xmss.get_index()
        transaction._data.transaction_hash = transaction.calculate_txhash()

        return transaction

    def _validate_custom(self):
        return True

    # noinspection PyBroadException
    def validate_extended(self, sv_list, blockheader):
        # FIXME: It is not good that we have a different signature here
        if blockheader.blocknumber > 1 and sv_list[self.txto].slave_public_key != self.PK:
            logger.warning('Stake validator doesnt own the Public key')
            logger.warning('Expected public key %s', sv_list[self.txto].slave_public_key)
            logger.warning('Found public key %s', self.PK)
            return False

        self.blockheader = blockheader

        return self.validate()


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

    def _validate_custom(self):
        # FIXME: This is missing
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

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        # TODO: Review get_message_hash is too different/inconsistent
        tmptxhash = bytes(self.prev_header_hash) + \
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

    def _validate_custom(self):
        if self.headerhash1 == self.headerhash2 and self.coinbase1.signature == self.coinbase2.signature:
            logger.info('Invalid DT txn')
            logger.info('coinbase1 and coinbase2 txn are same')
            return False

        if not self.validate_extended(self.headerhash1, self.coinbase1):
            return False

        if not self.validate_extended(self.headerhash2, self.coinbase2):
            return False

        return True

    def validate_extended(self, headerhash, coinbase):
        self.headerhash = headerhash
        self.coinbase = coinbase

        txhash = self.calculate_txhash()

        if coinbase.txhash != txhash:
            logger.info('Invalid Txhash')
            logger.warning('Found: %s Expected: %s', coinbase.txhash, txhash)
            return False

        if not coinbase.validate():
            return False

        return True


TYPEMAP = {
    qrl_pb2.Transaction.TRANSFER: TransferTransaction,
    qrl_pb2.Transaction.STAKE: StakeTransaction,
    qrl_pb2.Transaction.DESTAKE: DestakeTransaction,
    qrl_pb2.Transaction.COINBASE: CoinBase,
    qrl_pb2.Transaction.LATTICE: LatticePublicKey,
    qrl_pb2.Transaction.DUPLICATE: DuplicateTransaction
}
