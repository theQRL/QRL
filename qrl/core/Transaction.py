# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from abc import ABCMeta, abstractmethod

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import getAddress, bin2hstr

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
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
    def size(self):
        return self._data.ByteSize()

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
        return self._data.xmss_ots_index

    @staticmethod
    def get_ots_from_signature(signature):
        try:
            return int(bin2hstr(signature)[0:8], 16)
        except ValueError:
            raise ValueError('OTS Key Index: First 4 bytes of signature are invalid')

    @property
    def PK(self):
        return self._data.public_key

    @property
    def signature(self):
        return self._data.signature

    @property
    def xmss_ots_index(self):
        return self._data.xmss_ots_index

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

    @property
    def txhash(self) -> bytes:
        return self._data.transaction_hash

    def sign(self, xmss):
        self._data.signature = xmss.SIGN(self.txhash)

    @abstractmethod
    def apply_on_state(self, addresses_state):
        """
        This method, applies the changes on the state caused by txn.
        :param addr_from_state:
        :param addr_to_state:
        :return:
        """
        raise NotImplementedError

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

    @abstractmethod
    def set_effected_address(self, addresses_set: set):
        """
        Set all addresses which are being effected by the transaction
        :param addresses_set:
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

        if not isinstance(self, CoinBase) and getAddress('Q', self.PK) != self.txfrom.decode():
            raise ValueError('Public key and address dont match')

        if self.xmss_ots_index != self.get_ots_from_signature(self.signature):
            raise ValueError('xmss_ots_index and siganture ots index doesnt match')

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
                 str(self.xmss_ots_index).encode()
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

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.transfer.addr_to +
                                              str(self._data.transfer.amount).encode()
                                            )

    @staticmethod
    def create(addr_from: bytes, addr_to: bytes, amount, fee, xmss_pk, xmss_ots_index):
        transaction = TransferTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer.addr_to = addr_to
        transaction._data.transfer.amount = int(amount)  # FIXME: Review conversions for quantities
        transaction._data.fee = int(fee)  # FIXME: Review conversions for quantities
        transaction._data.xmss_ots_index = xmss_ots_index

        transaction._set_txhash()

        return transaction

    def _validate_custom(self):
        if self.amount <= 0:
            raise ValueError('[%s] Invalid amount = %d', bin2hstr(self.txhash), self.amount)

        if not (AddressState.address_is_valid(self.addr_from) and AddressState.address_is_valid(self.txto)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.addr_from, self.txto)
            return False

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

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= (self.amount + self.fee)
            addresses_state[self.txfrom].increase_nonce()
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)
            self.set_ots_key(addresses_state[self.txfrom], self.ots_key)
        if self.txto in addresses_state:
            addresses_state[self.txto].balance += self.amount
            addresses_state[self.txto].transaction_hashes.append(self.txhash)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.txto)


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

        transaction._data.addr_from = b'Q999999999999999999999999999999999999999999999999999999999999999999999999'
        transaction._data.fee = 0
        transaction._data.xmss_ots_index = xmss.get_index()
        transaction._data.public_key = bytes(xmss.pk())

        transaction._data.coinbase.addr_to = xmss.get_address()
        transaction._data.coinbase.amount = blockheader.block_reward + blockheader.fee_reward
        transaction._data.coinbase.block_number = blockheader.block_number
        transaction._data.coinbase.headerhash = blockheader.headerhash
        transaction._set_txhash()
        return transaction

    def _validate_custom(self):
        return True

    # noinspection PyBroadException
    def validate_extended(self, sv_dict, blockheader):
        if self.addr_from != b'Q999999999999999999999999999999999999999999999999999999999999999999999999':
            return False

        if not (AddressState.address_is_valid(self.addr_from) and AddressState.address_is_valid(self.txto)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.addr_from, self.txto)
            return False
        return self.validate()

    def apply_on_state(self, addresses_state):
        if self.txto in addresses_state:
            addresses_state[self.txto].balance += self.amount
            addresses_state[self.txto].increase_nonce()
            addresses_state[self.txto].transaction_hashes.append(self.txhash)
            self.set_ots_key(addresses_state[self.txto], self.ots_key)
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.amount
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.txto)


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

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
            self._get_concatenated_fields() +
            self._data.latticePK.kyber_pk +
            self._data.latticePK.dilithium_pk
        )

    @staticmethod
    def create(addr_from: bytes, fee, kyber_pk, dilithium_pk, xmss_pk, xmss_ots_index):
        transaction = LatticePublicKey()

        transaction._data.addr_from = addr_from
        transaction._data.fee = fee
        transaction._data.xmss_ots_index = xmss_ots_index
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

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.fee
            addresses_state[self.txfrom].add_lattice_pk(self)
            addresses_state[self.txfrom].increase_nonce()
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)
            self.set_ots_key(addresses_state[self.txfrom], self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)


class MessageTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(MessageTransaction, self).__init__(protobuf_transaction)
        if protobuf_transaction is None:
            self._data.type = qrl_pb2.Transaction.MESSAGE

    @property
    def message_hash(self):
        return self._data.message.message_hash

    def _set_txhash(self):
        self._data.transaction_hash = sha256(
                                              self._get_concatenated_fields() +
                                              self._data.message.message_hash
                                            )

    @staticmethod
    def create(addr_from: bytes, message_hash: bytes, fee: int, xmss_pk: bytes, xmss_ots_index: int):
        transaction = MessageTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.message.message_hash = message_hash
        transaction._data.fee = fee
        transaction._data.xmss_ots_index = xmss_ots_index

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

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.fee
            addresses_state[self.txfrom].increase_nonce()
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)
            self.set_ots_key(addresses_state[self.txfrom], self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)


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
               xmss_pk: bytes,
               xmss_ots_index: int):
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
        transaction._data.xmss_ots_index = xmss_ots_index

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

        if not AddressState.address_is_valid(self.addr_from):
            logger.warning('Invalid address addr_from: %s', self.addr_from)
            return False

        if not AddressState.address_is_valid(self.owner):
            logger.warning('Invalid address owner_addr: %s', self.owner)
            return False

        for address_balance in self.initial_balances:
            if not AddressState.address_is_valid(address_balance.address):
                logger.warning('Invalid address address in initial_balances: %s', address_balance.address)
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

    def apply_on_state(self, addresses_state):
        owner_processed = False
        txfrom_processed = False
        for initial_balance in self.initial_balances:
            if initial_balance.address == self.owner:
                owner_processed = True
            if initial_balance.address == self.txfrom:
                txfrom_processed = True
            if initial_balance.address in addresses_state:
                addresses_state[initial_balance.address].tokens[bin2hstr(self.txhash).encode()] += initial_balance.amount
                addresses_state[initial_balance.address].transaction_hashes.append(self.txhash)
        if self.owner in addresses_state and not owner_processed:
            addresses_state[self.owner].transaction_hashes.append(self.txhash)
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.fee
            addresses_state[self.txfrom].increase_nonce()
            if not txfrom_processed:
                addresses_state[self.txfrom].transaction_hashes.append(self.txhash)
            self.set_ots_key(addresses_state[self.txfrom], self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.owner)
        for initial_balance in self.initial_balances:
            addresses_set.add(initial_balance.address)


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
               xmss_pk: bytes,
               xmss_ots_index: int):
        transaction = TransferTokenTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer_token.token_txhash = token_txhash
        transaction._data.transfer_token.addr_to = addr_to
        transaction._data.transfer_token.amount = amount
        transaction._data.fee = int(fee)
        transaction._data.xmss_ots_index = xmss_ots_index

        transaction._set_txhash()

        return transaction

    def _validate_custom(self):
        if self.fee <= 0:
            raise ValueError('TransferTokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        if not (AddressState.address_is_valid(self.addr_from) and AddressState.address_is_valid(self.txto)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.addr_from, self.txto)
            return False

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

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].tokens[bin2hstr(self.token_txhash).encode()] -= self.amount
            if addresses_state[self.txfrom].tokens[bin2hstr(self.token_txhash).encode()] == 0:
                del addresses_state[self.txfrom].tokens[bin2hstr(self.token_txhash).encode()]
            addresses_state[self.txfrom].balance -= self.fee
            addresses_state[self.txfrom].increase_nonce()
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)
            self.set_ots_key(addresses_state[self.txfrom], self.ots_key)

        if self.txto in addresses_state:
            addresses_state[self.txto].transaction_hashes.append(self.txhash)
            addresses_state[self.txto].tokens[bin2hstr(self.token_txhash).encode()] += self.amount

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.txto)


TYPEMAP = {
    qrl_pb2.Transaction.TRANSFER: TransferTransaction,
    qrl_pb2.Transaction.COINBASE: CoinBase,
    qrl_pb2.Transaction.LATTICE: LatticePublicKey,
    qrl_pb2.Transaction.MESSAGE: MessageTransaction,
    qrl_pb2.Transaction.TOKEN: TokenTransaction,
    qrl_pb2.Transaction.TRANSFERTOKEN: TransferTokenTransaction,
}
