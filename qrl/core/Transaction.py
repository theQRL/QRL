# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from abc import ABCMeta, abstractmethod

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import getAddress, bin2hstr

from qrl.core import config, logger
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
    def fee(self):
        return self._data.fee

    @property
    def nonce(self):
        return self._data.nonce

    @property
    def txfrom(self):
        return self._data.addr_from

    @property
    def addr_from(self):
        return self._data.addr_from

    @property
    def ots_key(self):
        try:
            return int(bin2hstr(self._data.signature)[0:8], 16)
        except ValueError:
            raise ValueError('OTS Key Index: First 4 bytes of signature are invalid')

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
            qrl_pb2.Transaction.DUPLICATE: 'DUPLICATE',
            qrl_pb2.Transaction.VOTE: 'VOTE',
            qrl_pb2.Transaction.MESSAGE: 'MESSAGE',
            qrl_pb2.Transaction.TOKEN: 'TOKEN',
            qrl_pb2.Transaction.TRANSFERTOKEN: 'TRANSFERTOKEN'
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

    @staticmethod
    def ots_key_reuse(state_addr, ots_key):
        if state_addr is None:
            logger.info('-->> state_addr None not possible')
            return False

        offset = ots_key >> 3
        relative = ots_key % 8
        bitfield = bytearray(state_addr.ots_bitfield[offset])
        bit_value = (bitfield[0] >> relative) & 1

        if bit_value:
            return True

        return False

    @staticmethod
    def set_ots_key(state_addr, ots_key):
        offset = ots_key >> 3
        relative = ots_key % 8
        bitfield = bytearray(state_addr._data.ots_bitfield[offset])
        state_addr._data.ots_bitfield[offset] = bytes([bitfield[0] | (1 << relative)])

    @abstractmethod
    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        raise NotImplementedError

    @property
    def txhash(self) -> bytes:
        return self._data.transaction_hash

    def sign(self, xmss):
        self._data.signature = xmss.SIGN(self.txhash)

    @abstractmethod
    def _validate_custom(self) -> bool:
        """
        This is an extension point for derived classes validation
        If derived classes need additional field validation they should override this member
        """
        raise NotImplementedError

    @abstractmethod
    def _set_txhash(self) -> bytes:
        """
        Derived classes must need to implement this, to set the value of
        self.transaction_hash
        :return:
        """
        raise NotImplementedError

    def validate(self) -> bool:
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

    def validate_or_raise(self) -> bool:
        """
        This method will validate a transaction and raise exception if problems are found
        :return: True if the exception is valid, exceptions otherwise
        :rtype: bool
        """
        if not isinstance(self, TYPEMAP[self.subtype]):
            raise TypeError('Invalid subtype: Found: %s Expected: %s', type(self), TYPEMAP[self.subtype])

        if not self._validate_custom():
            raise ValueError("Custom validation failed")

        # FIXME: Why is coinbase skipped?
        if not isinstance(self, CoinBase) and not isinstance(self, Vote) and \
           getAddress('Q', self.PK) != self.txfrom.decode():
            raise ValueError('Public key and address dont match')

        if len(self.signature) == 0 or not XMSS.VERIFY(message=self.txhash,
                                                       signature=self.signature,
                                                       pk=self.PK):
            raise ValueError("Invalid xmss signature")

        return True

    def get_message_hash(self):
        # FIXME: refactor, review that things are not recalculated too often, cache, etc.
        return self.txhash

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)

    def _get_concatenated_fields(self):
        return (
                 str(self.subtype).encode() +
                 self.addr_from +
                 str(self.fee).encode() +
                 self.PK +
                 self.signature +
                 str(self.nonce).encode()
               )


class TransferTransaction(Transaction):
    """
    SimpleTransaction for the transaction of QRL from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(TransferTransaction, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.TRANSFER

    @property
    def txto(self):
        return self._data.transfer.addr_to

    @property
    def amount(self):
        return self._data.transfer.amount

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.txto +
                     str(self.amount).encode() +
                     str(self.fee).encode()
                    )

        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.transfer.addr_to +
                                              str(self._data.transfer.amount).encode()
                                            )

    @staticmethod
    def create(addr_from: bytes, addr_to: bytes, amount, fee, xmss_pk):
        transaction = TransferTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer.addr_to = addr_to
        transaction._data.transfer.amount = int(amount)  # FIXME: Review conversions for quantities
        transaction._data.fee = int(fee)  # FIXME: Review conversions for quantities

        transaction._set_txhash()

        return transaction

    def _validate_custom(self):
        if self.amount <= 0:
            raise ValueError('[%s] Invalid amount = %d', bin2hstr(self.txhash), self.amount)

        addr_expected = getAddress('Q', self.PK).encode()
        if addr_expected != self.addr_from:
            logger.warning('PK doesnt belong to the address')
            logger.warning('Address from PK : %s', addr_expected)
            logger.warning('Address found : %s', self.addr_from)
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, tx_state, transaction_pool):
        tx_balance = tx_state.balance

        if self.amount < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.amount:
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.amount)
            return False

        if self.ots_key_reuse(tx_state, self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.ots_key == self.ots_key:
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
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.STAKE

    @property
    def activation_blocknumber(self):
        return self._data.stake.activation_blocknumber

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
        tmptxhash = bin2hstr(tuple(self.hash)).encode()
        tmptxhash = (
                     str(self.subtype).encode() +
                     tmptxhash +
                     self.slave_public_key +
                     str(self.activation_blocknumber).encode()
                    )  # FIXME: stringify in standardized way
        # FIXME: the order in the dict may affect hash
        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              str(self._data.stake.activation_blocknumber).encode() +
                                              self._data.stake.slavePK +
                                              self._data.stake.hash
                                            )

    @staticmethod
    def create(activation_blocknumber: int,
               xmss: XMSS,
               slavePK: bytes,
               hashchain_terminator: bytes = None):
        """
        >>> s = StakeTransaction()
        >>> slave = XMSS(4)
        >>> isinstance(s.create(0, XMSS(4), slave.pk(), None), StakeTransaction)
        True
        """

        transaction = StakeTransaction()
        transaction._data.addr_from = bytes(xmss.get_address())
        transaction._data.public_key = bytes(xmss.pk())

        # Stake specific
        transaction._data.stake.activation_blocknumber = activation_blocknumber
        transaction._data.stake.slavePK = slavePK

        if hashchain_terminator is None:
            epoch = activation_blocknumber // config.dev.blocks_per_epoch
            # FIXME: We are using the same xmss for the hashchain???
            transaction._data.stake.hash = hashchain_reveal(xmss.get_seed_private(), epoch=epoch)
        else:
            transaction._data.stake.hash = hashchain_terminator

        transaction._set_txhash()
        return transaction

    def _validate_custom(self):
        addr_expected = getAddress('Q', self.PK).encode()
        if addr_expected != self.addr_from:
            logger.warning('PK doesnt belong to the address')
            logger.warning('Address from PK : %s', addr_expected)
            logger.warning('Address found : %s', self.addr_from)
            return False

        return True

    def validate_extended(self, tx_state):
        # TODO no need to transmit pubhash over the network
        # pubhash has to be calculated by the receiver
        if self.ots_key_reuse(tx_state, self.ots_key):
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
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.DESTAKE

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.pub
                    )
        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields()
                                            )

    @staticmethod
    def create(xmss):
        """
        >>> s = DestakeTransaction()
        >>> isinstance(s.create(XMSS(4)), DestakeTransaction)
        True
        """

        transaction = DestakeTransaction()
        transaction._data.addr_from = xmss.get_address()
        transaction._data.public_key = bytes(xmss.pk())
        transaction._set_txhash()
        return transaction

    def _validate_custom(self):
        return True

    def validate_extended(self, tx_state):
        if self.ots_key_reuse(tx_state, self.ots_key):
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
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.COINBASE

    @property
    def txto(self):
        return self._data.coinbase.addr_to

    @property
    def amount(self):
        return self._data.coinbase.amount

    @property
    def headerhash(self):
        return self._data.coinbase.headerhash

    @property
    def block_number(self):
        return self._data.coinbase.block_number

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        # FIXME: Avoid all intermediate conversions
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.txto +
                     self.headerhash +
                     str(self.block_number).encode() +
                     str(self.amount).encode()
                    )
        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.coinbase.addr_to +
                                              str(self._data.coinbase.amount).encode() +
                                              str(self._data.coinbase.block_number).encode() +
                                              self._data.coinbase.headerhash
                                            )

    @staticmethod
    def create(blockheader, xmss):
        transaction = CoinBase()

        transaction._data.addr_from = blockheader.stake_selector
        transaction._data.fee = 0
        transaction._data.public_key = bytes(xmss.pk())

        transaction._data.coinbase.addr_to = blockheader.stake_selector
        transaction._data.coinbase.amount = blockheader.block_reward + blockheader.fee_reward
        transaction._data.coinbase.block_number = blockheader.block_number
        transaction._data.coinbase.headerhash = blockheader.headerhash
        transaction._set_txhash()
        return transaction

    def _validate_custom(self):
        return True

    # noinspection PyBroadException
    def validate_extended(self, sv_dict, blockheader):
        # FIXME: It is not good that we have a different signature here
        if blockheader.block_number > 1 and sv_dict[self.txto].slave_public_key != self.PK:
            logger.warning('Stake validator doesnt own the Public key')
            logger.warning('Expected public key %s', sv_dict[self.txto].slave_public_key)
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
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.LATTICE

    @property
    def kyber_pk(self):
        return self._data.latticePK.kyber_pk

    @property
    def dilithium_pk(self):
        return self._data.latticePK.dilithium_pk

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.kyber_pk +
                     self.dilithium_pk +
                     str(self.fee).encode()
                    )
        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.latticePK.kyber_pk +
                                              self._data.latticePK.dilithium_pk
                                            )

    @staticmethod
    def create(addr_from: bytes, fee, kyber_pk, dilithium_pk, xmss_pk):
        transaction = LatticePublicKey()

        transaction._data.addr_from = addr_from
        transaction._data.fee = fee
        transaction._data.public_key = xmss_pk

        transaction._data.latticePK.kyber_pk = bytes(kyber_pk)
        transaction._data.latticePK.dilithium_pk = bytes(dilithium_pk)

        transaction._set_txhash()
        return transaction

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, tx_state, transaction_pool):
        tx_balance = tx_state.balance

        if self.fee < 0:
            logger.info('Lattice Txn: State validation failed %s : Negative fee %s', self.txhash, self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('Lattice Txn: State validation failed %s : Insufficient funds', self.txhash)
            logger.info('balance: %s, fee: %s', tx_balance, self.fee)
            return False

        if self.ots_key_reuse(tx_state, self.ots_key):
            logger.info('Lattice Txn: OTS Public key re-use detected %s', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.ots_key == self.ots_key:
                logger.info('Lattice Txn: OTS Public key re-use detected %s', self.txhash)
                return False

        return True

    def _validate_custom(self):
        # FIXME: This is missing
        return True


class DuplicateTransaction(Transaction):
    def __init__(self, protobuf_transaction=None):
        super(DuplicateTransaction, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.DUPLICATE

    @property
    def blocknumber(self):
        return self._data.duplicate.block_number

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
        # FIXME: Update the tmptxhash
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.prev_header_hash +
                     str(self.blocknumber).encode() +
                     self.headerhash
                    )
        # FIXME: Review. coinbase2?

        return bytes(sha256(tmptxhash))

    @staticmethod
    def create(block1, block2):
        transaction = DuplicateTransaction()

        transaction._data.duplicate.block_number = block1.block_number
        transaction._data.duplicate.prev_header_hash = block1.prev_blockheaderhash

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
        # FIXME: What is this? Why is being defined here????
        self.headerhash = headerhash
        self.coinbase = coinbase

        if not coinbase.validate():
            return False

        return True


class Vote(Transaction):
    """
    Vote Transaction must be signed by Slave XMSS only.
    """

    def __init__(self, protobuf_transaction=None):
        super(Vote, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.VOTE

    @property
    def blocknumber(self):
        return self._data.vote.block_number

    @property
    def headerhash(self):
        return self._data.vote.hash_header

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """

        tmptxhash = (
                     str(self.subtype).encode() +
                     self.addr_from +
                     str(self.blocknumber).encode() +
                     bin2hstr(self.headerhash).encode()
                    )

        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              str(self._data.vote.block_number).encode() +
                                              self._data.vote.hash_header
                                            )

    @staticmethod
    def create(blocknumber: int, headerhash: bytes, xmss):
        transaction = Vote()

        transaction._data.addr_from = xmss.get_address()
        transaction._data.vote.block_number = blocknumber
        transaction._data.vote.hash_header = headerhash

        transaction._data.public_key = xmss.pk()
        transaction._set_txhash()

        return transaction

    def _validate_custom(self):
        return True

    def validate_extended(self, tx_state, stake_validators_tracker):

        if self.ots_key_reuse(tx_state, self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.ots_key)
            return False

        if not stake_validators_tracker.contains_slave_pk(self.PK):
            logger.warning('Slave Public Key not found')
            logger.warning('Found public key %s', self.PK)
            return False

        return True


class MessageTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(MessageTransaction, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.MESSAGE

    @property
    def message_hash(self):
        return self._data.message.message_hash

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """

        tmptxhash = (
                     str(self.subtype).encode() +
                     self.message_hash +
                     str(self.fee).encode()
                    )

        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.message.message_hash
                                            )

    @staticmethod
    def create(addr_from: bytes, message_hash: bytes, fee: int, xmss_pk: bytes):
        transaction = MessageTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.message.message_hash = message_hash
        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk
        transaction._set_txhash()
        return transaction

    def _validate_custom(self) -> bool:
        if len(self.message_hash) > 80:
            logger.warning('Message hash length more than 80, %s', len(self.message_hash))
            return False
        addr_expected = getAddress('Q', self.PK).encode()
        if addr_expected != self.addr_from:
            logger.warning('PK doesnt belong to the address')
            logger.warning('Address from PK : %s', addr_expected)
            logger.warning('Address found : %s', self.addr_from)
            return False
        return True

    def validate_extended(self, tx_state, transaction_pool) -> bool:
        tx_balance = tx_state.balance

        if self.fee < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        if self.ots_key_reuse(tx_state, self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.ots_key == self.ots_key:
                logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
                return False

        return True


class TokenTransaction(Transaction):
    """
    TokenTransaction to create new Token.
    """

    def __init__(self, protobuf_transaction=None):
        super(TokenTransaction, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.TOKEN

    @property
    def symbol(self):
        return self._data.token.symbol

    @property
    def name(self):
        return self._data.token.name

    @property
    def owner(self):
        return self._data.token.owner

    @property
    def decimals(self):
        return self._data.token.decimals

    @property
    def initial_balances(self):
        return self._data.token.initial_balances

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.symbol +
                     self.name +
                     self.owner +
                     str(self.decimals).encode() +
                     str(self.fee).encode()
                    )

        for initial_balance in self._data.token.initial_balances:
            tmptxhash += initial_balance.address
            tmptxhash += str(initial_balance.amount).encode()

        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        tmptxhash = sha256(
                            self._get_concatenated_fields() +
                            self._data.token.symbol +
                            self._data.token.name +
                            self._data.token.owner +
                            str(self._data.token.decimals).encode()
                          )

        for initial_balance in self._data.token.initial_balances:
            tmptxhash += initial_balance.address
            tmptxhash += str(initial_balance.amount).encode()

        self._data.transaction_hash = sha256(tmptxhash)

    @staticmethod
    def create(addr_from: bytes,
               symbol: bytes,
               name: bytes,
               owner: bytes,
               decimals: int,
               initial_balances: list,
               fee: int,
               xmss_pk):
        transaction = TokenTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.token.symbol = symbol
        transaction._data.token.name = name
        transaction._data.token.owner = owner
        transaction._data.token.decimals = decimals

        for initial_balance in initial_balances:
            transaction._data.token.initial_balances.extend([initial_balance])

        transaction._data.fee = int(fee)

        transaction._set_txhash()

        return transaction

    def _validate_custom(self):
        if self.fee <= 0:
            raise ValueError('TokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        addr_expected = getAddress('Q', self.PK).encode()
        if addr_expected != self.addr_from:
            logger.warning('PK doesnt belong to the address')
            logger.warning('Address from PK : %s', addr_expected)
            logger.warning('Address found : %s', self.addr_from)
            return False

        for initial_balance in self._data.token.initial_balances:
            if initial_balance.amount <= 0:
                raise ValueError('TokenTransaction [%s] Invalid Amount = %s for address %s',
                                 bin2hstr(self.txhash),
                                 initial_balance.amount,
                                 initial_balance.address)

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, tx_state, transaction_pool):
        tx_balance = tx_state.balance

        if self.fee < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.fee:
            logger.info('TokenTxn State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if self.ots_key_reuse(tx_state, self.ots_key):
            logger.info('TokenTxn State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.ots_key == self.ots_key:
                logger.info('TokenTxn State validation failed for %s because: OTS Public key re-use detected',
                            self.txhash)
                return False

        return True


class TransferTokenTransaction(Transaction):
    """
    TransferTokenTransaction for the transaction of pre-existing Token from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(TransferTokenTransaction, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.TRANSFERTOKEN

    @property
    def token_txhash(self):
        return self._data.transfer_token.token_txhash

    @property
    def txto(self):
        return self._data.transfer_token.addr_to

    @property
    def amount(self):
        return self._data.transfer_token.amount

    def _get_hashable_bytes(self):
        """
        This method should return bytes that are to be hashed and represent the transaction
        :return: hashable bytes
        :rtype: bytes
        """
        tmptxhash = (
                     str(self.subtype).encode() +
                     self.token_txhash +
                     self.txto +
                     str(self.amount).encode() +
                     str(self.fee).encode()
                    )

        return bytes(sha256(tmptxhash))

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.transfer_token.addr_to +
                                              str(self._data.transfer_token.amount).encode()
                                            )

    @staticmethod
    def create(addr_from: bytes,
               token_txhash: bytes,
               addr_to: bytes,
               amount: int,
               fee: int,
               xmss_pk):
        transaction = TransferTokenTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer_token.token_txhash = token_txhash
        transaction._data.transfer_token.addr_to = addr_to
        transaction._data.transfer_token.amount = amount
        transaction._data.fee = int(fee)

        transaction._set_txhash()

        return transaction

    def _validate_custom(self):
        if self.fee <= 0:
            raise ValueError('TransferTokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        addr_expected = getAddress('Q', self.PK).encode()
        if addr_expected != self.addr_from:
            logger.warning('PK doesnt belong to the address')
            logger.warning('Address from PK : %s', addr_expected)
            logger.warning('Address found : %s', self.addr_from)
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, tx_state, transaction_pool):
        tx_balance = tx_state.balance

        if self.fee < 0 or self.amount < 0:
            logger.info('TransferTokenTransaction State validation failed for %s because: ', self.txhash)
            logger.info('Txn amount: %s, Fee: %s', self.amount, self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('TransferTokenTransaction State validation failed for %s because: Insufficient funds',
                        self.txhash)
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if self.ots_key_reuse(tx_state, self.ots_key):
            logger.info('TransferTokenTransaction State validation failed for %s because: OTS Public key re-use detected',
                        self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if txn.ots_key == self.ots_key:
                logger.info('TransferTokenTransaction State validation failed for %s because: OTS Public key re-use detected',
                            self.txhash)
                return False

        return True


TYPEMAP = {
    qrl_pb2.Transaction.TRANSFER: TransferTransaction,
    qrl_pb2.Transaction.STAKE: StakeTransaction,
    qrl_pb2.Transaction.DESTAKE: DestakeTransaction,
    qrl_pb2.Transaction.COINBASE: CoinBase,
    qrl_pb2.Transaction.LATTICE: LatticePublicKey,
    qrl_pb2.Transaction.DUPLICATE: DuplicateTransaction,
    qrl_pb2.Transaction.VOTE: Vote,
    qrl_pb2.Transaction.MESSAGE: MessageTransaction,
    qrl_pb2.Transaction.TOKEN: TokenTransaction,
    qrl_pb2.Transaction.TRANSFERTOKEN: TransferTokenTransaction,
}
