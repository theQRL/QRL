# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from abc import ABCMeta, abstractmethod

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import bin2hstr, QRLHelper, XmssFast

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.crypto.misc import sha256
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
    def type(self):
        return self._data.WhichOneof('transactionType')

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
        return self.get_ots_from_signature(self.signature)

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

    @staticmethod
    def from_pbdata(pbdata: qrl_pb2.Transaction):
        txtype = TYPEMAP[pbdata.WhichOneof('transactionType')]
        return txtype(pbdata)

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.Transaction()
        Parse(json_data, pbdata)
        return Transaction.from_pbdata(pbdata)

    @staticmethod
    def get_slave(tx):
        addr_from_pk = bytes(QRLHelper.getAddress(tx.PK))
        if addr_from_pk != tx.txfrom:
            return addr_from_pk
        return None

    @property
    def txhash(self) -> bytes:
        return self._data.transaction_hash

    def update_txhash(self):
        self._data.transaction_hash = sha256(
                                              self.get_hashable_bytes() +
                                              self.signature +
                                              self.PK
                                            )

    def get_hashable_bytes(self) -> bytes:
        """
        This method returns the hashes of the transaction data.
        :return:
        """
        raise NotImplementedError

    def sign(self, xmss):
        self._data.signature = xmss.sign(self.get_hashable_bytes())
        self.update_txhash()

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
    def set_effected_address(self, addresses_set: set):
        """
        Set all addresses which are being effected by the transaction
        :param addresses_set:
        :return:
        """
        raise NotImplementedError

    def validate_transaction_pool(self, transaction_pool):
        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            if self.PK != txn.PK:
                continue

            if txn.ots_key == self.ots_key:
                logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
                logger.info('Subtype %s', type(self))
                return False

        return True

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
        if not self._validate_custom():
            raise ValueError("Custom validation failed")

        if not XmssFast.verify(self.get_hashable_bytes(),
                               self.signature,
                               self.PK):
            raise ValueError("Invalid xmss signature")
        return True

    def validate_slave(self, addr_from_state, addr_from_pk_state):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if isinstance(self, CoinBase):
            master_address = self.txto
            allowed_access_types = [0, 1]
        else:
            master_address = self.txfrom
            allowed_access_types = [0]

        if addr_from_pk != master_address:
            if str(self.PK) not in addr_from_state.slave_pks_access_type:
                logger.warning('Public key and address dont match')
                return False

            access_type = addr_from_pk_state.slave_pks_access_type[str(self.PK)]
            if access_type not in allowed_access_types:
                logger.warning('Access Type %s', access_type)
                logger.warning('Slave Address doesnt have sufficient permission')
                return False

        return True

    def get_message_hash(self):
        # FIXME: refactor, review that things are not recalculated too often, cache, etc.
        return self.txhash

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data)


class TransferTransaction(Transaction):
    """
    SimpleTransaction for the transaction of QRL from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(TransferTransaction, self).__init__(protobuf_transaction)

    @property
    def addr_to(self):
        return self._data.transfer.addr_to

    @property
    def amount(self):
        return self._data.transfer.amount

    def get_hashable_bytes(self):
        # FIXME: Avoid using strings
        # Example blob = self.block_number.to_bytes(8, byteorder='big', signed=False)
        return sha256(
            self.addr_from +
            str(self.fee).encode() +
            self.addr_to +
            str(self.amount).encode()
                     )

    @staticmethod
    def create(addr_from: bytes, addr_to: bytes, amount, fee, xmss_pk):
        transaction = TransferTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer.addr_to = addr_to
        transaction._data.transfer.amount = int(amount)  # FIXME: Review conversions for quantities
        transaction._data.fee = int(fee)  # FIXME: Review conversions for quantities

        return transaction

    def _validate_custom(self):
        if self.amount <= 0:
            raise ValueError('[%s] Invalid amount = %d', bin2hstr(self.txhash), self.amount)

        if not (AddressState.address_is_valid(self.addr_from) and AddressState.address_is_valid(self.addr_to)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.addr_from, self.addr_to)
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state, addr_from_pk_state):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.amount < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.amount:
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.amount)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        return True

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= (self.amount + self.fee)
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        if self.addr_to in addresses_state:
            addresses_state[self.addr_to].balance += self.amount
            if self.addr_to != self.txfrom:
                addresses_state[self.addr_to].transaction_hashes.append(self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.txfrom != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.addr_to)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


class CoinBase(Transaction):
    """
    CoinBase is the type of transaction to credit the block_reward to
    the stake selector who created the block.
    """

    def __init__(self, protobuf_transaction=None):
        super(CoinBase, self).__init__(protobuf_transaction)

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

    def get_hashable_bytes(self):
        # FIXME: Avoid using strings
        # Example blob = self.block_number.to_bytes(8, byteorder='big', signed=False)
        return sha256(
                      self.addr_from +
                      str(self.fee).encode() +
                      self.txto +
                      str(self.amount).encode() +
                      str(self.block_number).encode() +
                      self.headerhash
                      )

    @staticmethod
    def create(blockheader, xmss, master_address):
        transaction = CoinBase()

        transaction._data.addr_from = config.dev.coinbase_address
        transaction._data.fee = 0
        transaction._data.public_key = bytes(xmss.pk)

        transaction._data.coinbase.addr_to = master_address
        transaction._data.coinbase.amount = blockheader.block_reward + blockheader.fee_reward
        transaction._data.coinbase.block_number = blockheader.block_number
        transaction._data.coinbase.headerhash = blockheader.headerhash

        return transaction

    def _validate_custom(self):
        if self.fee != 0:
            logger.warning('Fee for coinbase transaction should be 0')
            return False

        return True

    # noinspection PyBroadException
    def validate_extended(self, addr_from_state, addr_from_pk_state):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        if self.addr_from != config.dev.coinbase_address:
            return False

        if not (AddressState.address_is_valid(self.addr_from) and AddressState.address_is_valid(self.txto)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.addr_from, self.txto)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.warning('CoinBase Txn: OTS Public key re-use detected %s', self.txhash)
            return False

        return True

    def apply_on_state(self, addresses_state):
        if self.txto in addresses_state:
            addresses_state[self.txto].balance += self.amount
            addresses_state[self.txto].transaction_hashes.append(self.txhash)

        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.amount
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.txto != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.txto)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


class LatticePublicKey(Transaction):
    """
    LatticePublicKey transaction to store the public key.
    This transaction has been designed for Ephemeral Messaging.
    """

    def __init__(self, protobuf_transaction=None):
        super(LatticePublicKey, self).__init__(protobuf_transaction)

    @property
    def kyber_pk(self):
        return self._data.latticePK.kyber_pk

    @property
    def dilithium_pk(self):
        return self._data.latticePK.dilithium_pk

    def get_hashable_bytes(self):
        # FIXME: Avoid using strings
        # Example blob = self.block_number.to_bytes(8, byteorder='big', signed=False)
        return sha256(
                       self.addr_from +
                       str(self.fee).encode() +
                       self.kyber_pk +
                       self.dilithium_pk
                     )

    @staticmethod
    def create(addr_from: bytes, fee, kyber_pk, dilithium_pk, xmss_pk):
        transaction = LatticePublicKey()

        transaction._data.addr_from = addr_from
        transaction._data.fee = fee
        transaction._data.public_key = xmss_pk

        transaction._data.latticePK.kyber_pk = bytes(kyber_pk)
        transaction._data.latticePK.dilithium_pk = bytes(dilithium_pk)

        return transaction

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state, addr_from_pk_state):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('Lattice Txn: State validation failed %s : Negative fee %s', self.txhash, self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('Lattice Txn: State validation failed %s : Insufficient funds', self.txhash)
            logger.info('balance: %s, fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
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
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.txfrom != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


class MessageTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(MessageTransaction, self).__init__(protobuf_transaction)

    @property
    def message_hash(self):
        return self._data.message.message_hash

    def get_hashable_bytes(self):
        return sha256(
                      self.addr_from +
                      str(self.fee).encode() +
                      self.message_hash
                     )

    @staticmethod
    def create(addr_from: bytes, message_hash: bytes, fee: int, xmss_pk: bytes):
        transaction = MessageTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.message.message_hash = message_hash
        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk

        return transaction

    def _validate_custom(self) -> bool:
        if len(self.message_hash) > 80:
            logger.warning('Message hash length more than 80, %s', len(self.message_hash))
            return False
        return True

    def validate_extended(self, addr_from_state, addr_from_pk_state) -> bool:
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        return True

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.fee
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.txfrom != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


class TokenTransaction(Transaction):
    """
    TokenTransaction to create new Token.
    """

    def __init__(self, protobuf_transaction=None):
        super(TokenTransaction, self).__init__(protobuf_transaction)

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

    def get_hashable_bytes(self):
        # FIXME: Avoid using strings
        # Example blob = self.block_number.to_bytes(8, byteorder='big', signed=False)
        # FIXME: Use a separator between fields..
        tmptxhash = sha256(
                            self.addr_from +
                            str(self.fee).encode() +
                            self.symbol +
                            self.name +
                            self.owner +
                            str(self._data.token.decimals).encode()
                          )

        for initial_balance in self._data.token.initial_balances:
            tmptxhash += initial_balance.address
            tmptxhash += str(initial_balance.amount).encode()

        return sha256(tmptxhash)

    @staticmethod
    def create(addr_from: bytes,
               symbol: bytes,
               name: bytes,
               owner: bytes,
               decimals: int,
               initial_balances: list,
               fee: int,
               xmss_pk: bytes):
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

        return transaction

    def _validate_custom(self):
        if self.fee <= 0:
            raise ValueError('TokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        for initial_balance in self._data.token.initial_balances:
            if initial_balance.amount <= 0:
                raise ValueError('TokenTransaction [%s] Invalid Amount = %s for address %s',
                                 bin2hstr(self.txhash),
                                 initial_balance.amount,
                                 initial_balance.address)

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state, addr_from_pk_state):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

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

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('TokenTxn State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        return True

    def apply_on_state(self, addresses_state):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        owner_processed = False
        txfrom_processed = False
        addr_from_pk_processed = False

        for initial_balance in self.initial_balances:
            if initial_balance.address == self.owner:
                owner_processed = True
            if initial_balance.address == self.txfrom:
                txfrom_processed = True
            if initial_balance.address == addr_from_pk:
                addr_from_pk_processed = True
            if initial_balance.address in addresses_state:
                addresses_state[initial_balance.address].tokens[bin2hstr(self.txhash).encode()] += initial_balance.amount
                addresses_state[initial_balance.address].transaction_hashes.append(self.txhash)

        if self.owner in addresses_state and not owner_processed:
            addresses_state[self.owner].transaction_hashes.append(self.txhash)

        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.fee
            if not txfrom_processed:
                addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        if addr_from_pk in addresses_state:
            if self.txfrom != addr_from_pk:
                if not addr_from_pk_processed:
                    addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.owner)
        for initial_balance in self.initial_balances:
            addresses_set.add(initial_balance.address)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


class TransferTokenTransaction(Transaction):
    """
    TransferTokenTransaction for the transaction of pre-existing Token from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(TransferTokenTransaction, self).__init__(protobuf_transaction)

    @property
    def token_txhash(self):
        return self._data.transfer_token.token_txhash

    @property
    def txto(self):
        return self._data.transfer_token.addr_to

    @property
    def amount(self):
        return self._data.transfer_token.amount

    def get_hashable_bytes(self):
        # FIXME: Avoid using strings
        # Example blob = self.block_number.to_bytes(8, byteorder='big', signed=False)
        # FIXME: Use a separator between fields..
        return sha256(
                       self.addr_from +
                       str(self.fee).encode() +
                       self.token_txhash +
                       self.txto +
                       str(self.amount).encode()
                     )

    @staticmethod
    def create(addr_from: bytes,
               token_txhash: bytes,
               addr_to: bytes,
               amount: int,
               fee: int,
               xmss_pk: bytes):
        transaction = TransferTokenTransaction()

        transaction._data.addr_from = addr_from
        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer_token.token_txhash = token_txhash
        transaction._data.transfer_token.addr_to = addr_to
        transaction._data.transfer_token.amount = amount
        transaction._data.fee = int(fee)

        return transaction

    def _validate_custom(self):
        if self.fee <= 0:
            raise ValueError('TransferTokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        if not (AddressState.address_is_valid(self.addr_from) and AddressState.address_is_valid(self.txto)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.addr_from, self.txto)
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state, addr_from_pk_state):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0 or self.amount < 0:
            logger.info('TransferTokenTransaction State validation failed for %s because: ', self.txhash)
            logger.info('Txn amount: %s, Fee: %s', self.amount, self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('TransferTokenTransaction State validation failed for %s because: Insufficient funds',
                        self.txhash)
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
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
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        if self.txto in addresses_state:
            if self.txfrom != self.txto:
                addresses_state[self.txto].transaction_hashes.append(self.txhash)
            addresses_state[self.txto].tokens[bin2hstr(self.token_txhash).encode()] += self.amount

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.txfrom != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(self.txto)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


class SlaveTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(SlaveTransaction, self).__init__(protobuf_transaction)

    @property
    def slave_pks(self):
        return self._data.slave.slave_pks

    @property
    def access_types(self):
        return self._data.slave.access_types

    def get_hashable_bytes(self):
        tmptxhash = sha256(
                            self.addr_from +
                            str(self.fee).encode()
                          )

        for index in range(0, len(self.slave_pks)):
            tmptxhash = sha256(tmptxhash + self.slave_pks[index] + str(self.access_types[index]).encode())

        return tmptxhash

    @staticmethod
    def create(addr_from: bytes, slave_pks: list, access_types: list, fee: int, xmss_pk: bytes):
        transaction = SlaveTransaction()

        transaction._data.addr_from = addr_from
        for slave_pk in slave_pks:
            transaction._data.slave.slave_pks.append(slave_pk)
        for access_type in access_types:
            transaction._data.slave.access_types.append(access_type)
        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk

        return transaction

    def _validate_custom(self) -> bool:
        if len(self.slave_pks) > 100 or len(self.access_types) > 100:
            logger.warning('List has more than 100 slave pks or access_types')
            logger.warning('Slave pks len %s', len(self.slave_pks))
            logger.warning('Access types len %s', len(self.access_types))
            return False

        if len(self.slave_pks) != len(self.access_types):
            logger.warning('Number of slave pks are not equal to the number of access types provided')
            logger.warning('Slave pks len %s', len(self.slave_pks))
            logger.warning('Access types len %s', len(self.access_types))
            return False

        for access_type in self.access_types:
            if access_type not in [0, 1]:
                logger.warning('Invalid Access type %s', access_type)
                return False

        return True

    def validate_extended(self, addr_from_state, addr_from_pk_state) -> bool:
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('Slave: State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.fee:
            logger.info('Slave: State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('Slave: State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        return True

    def apply_on_state(self, addresses_state):
        if self.txfrom in addresses_state:
            addresses_state[self.txfrom].balance -= self.fee
            for index in range(0, len(self.slave_pks)):
                addresses_state[self.txfrom].add_slave_pks_access_type(self.slave_pks[index],
                                                                       self.access_types[index])
            addresses_state[self.txfrom].transaction_hashes.append(self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.txfrom != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def set_effected_address(self, addresses_set: set):
        addresses_set.add(self.txfrom)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))


TYPEMAP = {
    'transfer': TransferTransaction,
    'coinbase': CoinBase,
    'latticePK': LatticePublicKey,
    'message': MessageTransaction,
    'token': TokenTransaction,
    'transfer_token': TransferTokenTransaction,
    'slave': SlaveTransaction
}

CODEMAP = {
    'transfer': 1,
    'coinbase': 2,
    'latticePK': 3,
    'message': 4,
    'token': 5,
    'transfer_token': 6,
    'slave': 7
}
