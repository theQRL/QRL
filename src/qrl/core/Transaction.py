# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from math import log, floor
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

    def __lt__(self, tx):
        if self.fee < tx.fee:
            return True
        return False

    def __gt__(self, tx):
        if self.fee > tx.fee:
            return True
        return False

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
    def master_addr(self):
        return self._data.master_addr

    @property
    def addr_from(self):
        if self.master_addr:
            return self.master_addr

        return bytes(QRLHelper.getAddress(self.PK))

    @property
    def ots_key(self):
        return self.get_ots_from_signature(self.signature)

    @staticmethod
    def get_ots_from_signature(signature):
        try:
            return int(bin2hstr(signature)[0:8], 16)
        except ValueError:
            raise ValueError('OTS Key Index: First 4 bytes of signature are invalid')

    @staticmethod
    def calc_allowed_decimals(value):
        if not isinstance(value, int):
            raise ValueError('value should be of integer type')
        if value == 0:
            raise ValueError('Invalid input 0')

        # floor value could be negative, so return 0 when the floor value is negative
        return max(floor(19 - log(value, 10)), 0)

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
        if addr_from_pk != tx.addr_from:
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
    def apply_state_changes(self, addresses_state):
        """
        This method, applies the changes on the state caused by txn.
        :return:
        """
        raise NotImplementedError

    def _apply_state_changes_for_PK(self, addresses_state):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.addr_from != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    @abstractmethod
    def revert_state_changes(self, addresses_state, state):
        """
        This method reverts the changes on the state caused by txn.
        :return:
        """
        raise NotImplementedError

    def _revert_state_changes_for_PK(self, addresses_state, state):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        if addr_from_pk in addresses_state:
            if self.addr_from != addr_from_pk:
                addresses_state[addr_from_pk].transaction_hashes.remove(self.txhash)
            addresses_state[addr_from_pk].decrease_nonce()
            addresses_state[addr_from_pk].unset_ots_key(self.ots_key, state)

    def set_affected_address(self, addresses_set: set):
        addresses_set.add(self.addr_from)
        addresses_set.add(bytes(QRLHelper.getAddress(self.PK)))

    @abstractmethod
    def _validate_custom(self) -> bool:
        """
        This is an extension point for derived classes validation
        If derived classes need additional field validation they should override this member
        """
        raise NotImplementedError

    def validate_transaction_pool(self, transaction_pool):
        for tx_set in transaction_pool:
            txn = tx_set[1].transaction
            if txn.txhash == self.txhash:
                continue

            if self.PK != txn.PK:
                continue

            if txn.ots_key == self.ots_key:
                logger.info('State validation failed for %s because: OTS Public key re-use detected', bin2hstr(self.txhash))
                logger.info('Subtype %s', type(self))
                return False

        return True

    def validate(self) -> bool:
        """
        This method calls validate_or_raise, logs any failure and returns True or False accordingly
        The main purpose is to avoid exceptions and accommodate legacy code
        :return: True is the transaction is valid
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

    def validate_slave(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        # Validate Slave for CoinBase txn is no more required
        if isinstance(self, CoinBase):
            master_address = self.addr_to
            allowed_access_types = [0, 1]
        else:
            master_address = self.addr_from
            allowed_access_types = [0]

        if self.master_addr == addr_from_pk:
            logger.warning('Matching master_addr field and address from PK')
            return False

        if addr_from_pk != master_address:
            if str(self.PK) not in addr_from_state.slave_pks_access_type:
                logger.warning("Public key and address don't match")
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
    def addrs_to(self):
        return self._data.transfer.addrs_to

    @property
    def total_amount(self):
        total_amount = 0
        for amount in self.amounts:
            total_amount += amount
        return total_amount

    @property
    def amounts(self):
        return self._data.transfer.amounts

    def get_hashable_bytes(self):
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False))

        for index in range(0, len(self.addrs_to)):
            tmptxhash = (tmptxhash +
                         self.addrs_to[index] +
                         self.amounts[index].to_bytes(8, byteorder='big', signed=False))

        return sha256(tmptxhash)

    @staticmethod
    def create(addrs_to: list, amounts: list, fee, xmss_pk, master_addr: bytes = None):
        transaction = TransferTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.public_key = bytes(xmss_pk)

        for addr_to in addrs_to:
            transaction._data.transfer.addrs_to.append(addr_to)

        for amount in amounts:
            transaction._data.transfer.amounts.append(amount)

        transaction._data.fee = int(fee)  # FIXME: Review conversions for quantities

        return transaction

    def _validate_custom(self):
        for amount in self.amounts:
            if amount == 0:
                logger.warning('Amount cannot be 0', self.amounts)
                logger.warning('Invalid TransferTransaction')
                return False

        if self.fee < 0:
            raise ValueError('TransferTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        if (len(self.addrs_to) > config.dev.transaction_multi_output_limit or
                len(self.addrs_to) > config.dev.transaction_multi_output_limit):
            logger.warning('[TransferTransaction] Number of addresses exceeds max limit')
            logger.warning('Number of addresses %s', len(self.addrs_to))
            logger.warning('Number of amounts %s', len(self.amounts))
            return False

        if len(self.addrs_to) != len(self.amounts):
            logger.warning('[TransferTransaction] Mismatch number of addresses to & amounts')
            logger.warning('>> Length of addresses_to %s', len(self.addrs_to))
            logger.warning('>> Length of amounts %s', len(self.amounts))
            return False

        if not AddressState.address_is_valid(self.addr_from):
            logger.warning('[TransferTransaction] Invalid address addr_from: %s', self.addr_from)
            return False

        for addr_to in self.addrs_to:
            if not AddressState.address_is_valid(addr_to):
                logger.warning('[TransferTransaction] Invalid address addr_to: %s', addr_to)
                return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance
        total_amount = self.total_amount

        if tx_balance < total_amount + self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, fee: %s, amount: %s', tx_balance, self.fee, total_amount)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', bin2hstr(self.txhash))
            return False

        return True

    def apply_state_changes(self, addresses_state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= (self.total_amount + self.fee)
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            if addr_to in addresses_state:
                addresses_state[addr_to].balance += amount
                if addr_to == self.addr_from:
                    continue
                addresses_state[addr_to].transaction_hashes.append(self.txhash)

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += (self.total_amount + self.fee)
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            if addr_to in addresses_state:
                addresses_state[addr_to].balance -= amount
                if addr_to == self.addr_from:
                    continue
                addresses_state[addr_to].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, state)

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        for addr_to in self.addrs_to:
            addresses_set.add(addr_to)


class CoinBase(Transaction):
    """
    CoinBase is the type of transaction to credit the block_reward to
    the stake selector who created the block.
    """

    def __init__(self, protobuf_transaction=None):
        super(CoinBase, self).__init__(protobuf_transaction)

    @property
    def addr_to(self):
        return self._data.coinbase.addr_to

    @property
    def amount(self):
        return self._data.coinbase.amount

    def get_hashable_bytes(self):
        # nonce only added to the hashable bytes of CoinBase
        return sha256(
            self.master_addr +
            self.addr_to +
            self.nonce.to_bytes(8, byteorder='big', signed=False) +
            self.amount.to_bytes(8, byteorder='big', signed=False)
        )

    @staticmethod
    def create(amount, miner_address, block_number):
        transaction = CoinBase()
        transaction._data.master_addr = config.dev.coinbase_address
        transaction._data.coinbase.addr_to = miner_address
        transaction._data.coinbase.amount = amount
        transaction._data.nonce = block_number + 1
        transaction._data.transaction_hash = transaction.get_hashable_bytes()

        return transaction

    def update_mining_address(self, mining_address: bytes):
        self._data.coinbase.addr_to = mining_address
        self._data.transaction_hash = self.get_hashable_bytes()

    def _validate_custom(self):
        if self.fee != 0:
            logger.warning('Fee for coinbase transaction should be 0')
            return False

        return True

    # noinspection PyBroadException
    def validate_extended(self):
        if self.master_addr != config.dev.coinbase_address:
            logger.warning('Master address doesnt match with coinbase_address')
            logger.warning('%s %s', self.master_addr, config.dev.coinbase_address)
            return False

        if not (AddressState.address_is_valid(self.master_addr) and AddressState.address_is_valid(self.addr_to)):
            logger.warning('Invalid address addr_from: %s addr_to: %s', self.master_addr, self.addr_to)
            return False

        return self._validate_custom()

    def apply_state_changes(self, addresses_state):
        if self.addr_to in addresses_state:
            addresses_state[self.addr_to].balance += self.amount
            addresses_state[self.addr_to].transaction_hashes.append(self.txhash)

        addr_from = config.dev.coinbase_address

        if self.master_addr in addresses_state:
            addresses_state[self.master_addr].balance -= self.amount
            addresses_state[self.master_addr].transaction_hashes.append(self.txhash)
            addresses_state[addr_from].increase_nonce()

    def revert_state_changes(self, addresses_state, state):
        if self.addr_to in addresses_state:
            addresses_state[self.addr_to].balance -= self.amount
            addresses_state[self.addr_to].transaction_hashes.remove(self.txhash)

        addr_from = config.dev.coinbase_address

        if self.master_addr in addresses_state:
            addresses_state[self.master_addr].balance += self.amount
            addresses_state[self.master_addr].transaction_hashes.remove(self.txhash)
            addresses_state[addr_from].decrease_nonce()

    def set_affected_address(self, addresses_set: set):
        addresses_set.add(self.master_addr)
        addresses_set.add(self.addr_to)


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
        return sha256(
            self.master_addr +
            self.fee.to_bytes(8, byteorder='big', signed=False) +
            self.kyber_pk +
            self.dilithium_pk
        )

    @staticmethod
    def create(fee, kyber_pk, dilithium_pk, xmss_pk, master_addr: bytes = None):
        transaction = LatticePublicKey()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.fee = fee
        transaction._data.public_key = xmss_pk

        transaction._data.latticePK.kyber_pk = bytes(kyber_pk)
        transaction._data.latticePK.dilithium_pk = bytes(dilithium_pk)

        return transaction

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('Lattice Txn: State validation failed %s : Negative fee %s', bin2hstr(self.txhash), self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('Lattice Txn: State validation failed %s : Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('Lattice Txn: OTS Public key re-use detected %s', bin2hstr(self.txhash))
            return False

        return True

    def _validate_custom(self):
        # FIXME: This is missing
        return True

    def apply_state_changes(self, addresses_state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= self.fee
            addresses_state[self.addr_from].add_lattice_pk(self)
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            addresses_state[self.addr_from].remove_lattice_pk(self)
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, state)


class MessageTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(MessageTransaction, self).__init__(protobuf_transaction)

    @property
    def message_hash(self):
        return self._data.message.message_hash

    def get_hashable_bytes(self):
        return sha256(
            self.master_addr +
            self.fee.to_bytes(8, byteorder='big', signed=False) +
            self.message_hash
        )

    @staticmethod
    def create(message_hash: bytes, fee: int, xmss_pk: bytes, master_addr: bytes = None):
        transaction = MessageTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.message.message_hash = message_hash
        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk

        return transaction

    def _validate_custom(self) -> bool:
        if len(self.message_hash) > 80:
            logger.warning('Message length cannot be more than 80')
            logger.warning('Found message length %s', len(self.message_hash))
            return False

        if len(self.message_hash) == 0:
            logger.warning('Message cannot be empty')
            return False

        return True

    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState) -> bool:
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('State validation failed for %s because: Negative send', bin2hstr(self.txhash))
            return False

        if tx_balance < self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('State validation failed for %s because: OTS Public key re-use detected', bin2hstr(self.txhash))
            return False

        return True

    def apply_state_changes(self, addresses_state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= self.fee
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, state)


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
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False) +
                     self.symbol +
                     self.name +
                     self.owner +
                     self._data.token.decimals.to_bytes(8, byteorder='big', signed=False))

        for initial_balance in self._data.token.initial_balances:
            tmptxhash += initial_balance.address
            tmptxhash += initial_balance.amount.to_bytes(8, byteorder='big', signed=False)

        return sha256(tmptxhash)

    @staticmethod
    def create(symbol: bytes,
               name: bytes,
               owner: bytes,
               decimals: int,
               initial_balances: list,
               fee: int,
               xmss_pk: bytes,
               master_addr: bytes = None):
        transaction = TokenTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

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
        if len(self.symbol) > config.dev.max_token_symbol_length:
            logger.warning('Token Symbol Length exceeds maximum limit')
            logger.warning('Found Symbol Length %s', len(self.symbol))
            logger.warning('Expected Symbol length %s', config.dev.max_token_symbol_length)
            return False

        if len(self.name) > config.dev.max_token_name_length:
            logger.warning('Token Name Length exceeds maximum limit')
            logger.warning('Found Name Length %s', len(self.symbol))
            logger.warning('Expected Name length %s', config.dev.max_token_name_length)
            return False

        if len(self.symbol) == 0:
            logger.warning('Missing Token Symbol')
            return False

        if len(self.name) == 0:
            logger.warning('Missing Token Name')
            return False

        if len(self.initial_balances) == 0:
            logger.warning('Invalid Token Transaction, without any initial balance')
            return False

        sum_of_initial_balances = 0
        for initial_balance in self.initial_balances:
            sum_of_initial_balances += initial_balance.amount
            if initial_balance.amount == 0:
                logger.warning('Invalid Initial Amount in Token Transaction')
                logger.warning('Address %s | Amount %s', initial_balance.address, initial_balance.amount)
                return False

        allowed_decimals = self.calc_allowed_decimals(sum_of_initial_balances)

        if self.decimals > allowed_decimals:
            logger.warning('Decimal is greater than maximum allowed decimal')
            logger.warning('Allowed Decimal %s', allowed_decimals)
            logger.warning('Decimals Found %s', self.decimals)
            return False

        if self.fee < 0:
            raise ValueError('TokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        for initial_balance in self._data.token.initial_balances:
            if initial_balance.amount <= 0:
                raise ValueError('TokenTransaction [%s] Invalid Amount = %s for address %s',
                                 bin2hstr(self.txhash),
                                 initial_balance.amount,
                                 initial_balance.address)

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

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
            logger.info('TokenTxn State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('TokenTxn State validation failed for %s because: OTS Public key re-use detected', bin2hstr(self.txhash))
            return False

        return True

    def apply_state_changes(self, addresses_state):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        owner_processed = False
        addr_from_processed = False
        addr_from_pk_processed = False

        for initial_balance in self.initial_balances:
            if initial_balance.address == self.owner:
                owner_processed = True
            if initial_balance.address == self.addr_from:
                addr_from_processed = True
            if initial_balance.address == addr_from_pk:
                addr_from_pk_processed = True
            if initial_balance.address in addresses_state:
                addresses_state[initial_balance.address].tokens[
                    bin2hstr(self.txhash)] += initial_balance.amount
                addresses_state[initial_balance.address].transaction_hashes.append(self.txhash)

        if self.owner in addresses_state and not owner_processed:
            addresses_state[self.owner].transaction_hashes.append(self.txhash)

        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= self.fee
            if not addr_from_processed:
                addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        if addr_from_pk in addresses_state:
            if self.addr_from != addr_from_pk:
                if not addr_from_pk_processed:
                    addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def revert_state_changes(self, addresses_state, state):
        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        owner_processed = False
        addr_from_processed = False
        addr_from_pk_processed = False

        for initial_balance in self.initial_balances:
            if initial_balance.address == self.owner:
                owner_processed = True
            if initial_balance.address == self.addr_from:
                addr_from_processed = True
            if initial_balance.address == addr_from_pk:
                addr_from_pk_processed = True
            if initial_balance.address in addresses_state:
                token_tx_hash = bin2hstr(self.txhash)
                addresses_state[initial_balance.address].tokens[
                    token_tx_hash] -= initial_balance.amount
                if addresses_state[initial_balance.address].tokens[token_tx_hash] == 0:
                    del addresses_state[initial_balance.address].tokens[token_tx_hash]
                addresses_state[initial_balance.address].transaction_hashes.remove(self.txhash)

        if self.owner in addresses_state and not owner_processed:
            addresses_state[self.owner].transaction_hashes.remove(self.txhash)

        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            if not addr_from_processed:
                addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        if addr_from_pk in addresses_state:
            if self.addr_from != addr_from_pk:
                if not addr_from_pk_processed:
                    addresses_state[addr_from_pk].transaction_hashes.remove(self.txhash)
            addresses_state[addr_from_pk].decrease_nonce()
            addresses_state[addr_from_pk].unset_ots_key(self.ots_key, state)

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        addresses_set.add(self.owner)
        for initial_balance in self.initial_balances:
            addresses_set.add(initial_balance.address)


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
    def addrs_to(self):
        return self._data.transfer_token.addrs_to

    @property
    def total_amount(self):
        total_amount = 0
        for amount in self.amounts:
            total_amount += amount

        return total_amount

    @property
    def amounts(self):
        return self._data.transfer_token.amounts

    def get_hashable_bytes(self):
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False) +
                     self.token_txhash)

        for index in range(0, len(self.addrs_to)):
            tmptxhash = (tmptxhash +
                         self.addrs_to[index] +
                         self.amounts[index].to_bytes(8, byteorder='big', signed=False))

        return sha256(tmptxhash)

    @staticmethod
    def create(token_txhash: bytes,
               addrs_to: list,
               amounts: list,
               fee: int,
               xmss_pk: bytes,
               master_addr: bytes = None):
        transaction = TransferTokenTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.transfer_token.token_txhash = token_txhash

        for addr_to in addrs_to:
            transaction._data.transfer_token.addrs_to.append(addr_to)

        for amount in amounts:
            transaction._data.transfer_token.amounts.append(amount)

        transaction._data.fee = int(fee)

        return transaction

    def _validate_custom(self):
        for amount in self.amounts:
            if amount == 0:
                logger.warning('Amount cannot be 0', self.amounts)
                logger.warning('TransferTokenTransaction')
                return False

        if self.fee < 0:
            raise ValueError('TransferTokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        if (len(self.addrs_to) > config.dev.transaction_multi_output_limit or
                len(self.amounts) > config.dev.transaction_multi_output_limit):
            logger.warning('[TransferTokenTransaction] Number of addresses or amounts exceeds max limit')
            logger.warning('Number of addresses %s', len(self.addrs_to))
            logger.warning('Number of amounts %s', len(self.amounts))
            return False

        if len(self.addrs_to) != len(self.amounts):
            logger.warning('[TransferTokenTransaction] Mismatch number of addresses to & amounts')
            logger.warning('>> Length of addresses_to %s', len(self.addrs_to))
            logger.warning('>> Length of amounts %s', len(self.amounts))
            return False

        if not AddressState.address_is_valid(self.addr_from):
            logger.warning('[TransferTokenTransaction] Invalid address addr_from: %s', self.addr_from)
            return False

        for addr_to in self.addrs_to:
            if not AddressState.address_is_valid(addr_to):
                logger.warning('[TransferTokenTransaction] Invalid address addr_to: %s', addr_to)
                return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance
        total_amount = self.total_amount
        if self.fee < 0 or total_amount < 0:
            logger.info('TransferTokenTransaction State validation failed for %s because: ', bin2hstr(self.txhash))
            logger.info('Txn amount: %s, Fee: %s', total_amount, self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('TransferTokenTransaction State validation failed for %s because: Insufficient funds',
                        bin2hstr(self.txhash))
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info(
                'TransferTokenTransaction State validation failed for %s because: OTS Public key re-use detected',
                bin2hstr(self.txhash))
            return False

        return True

    def apply_state_changes(self, addresses_state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].tokens[bin2hstr(self.token_txhash).encode()] -= self.total_amount
            if addresses_state[self.addr_from].tokens[bin2hstr(self.token_txhash).encode()] == 0:
                del addresses_state[self.addr_from].tokens[bin2hstr(self.token_txhash).encode()]
            addresses_state[self.addr_from].balance -= self.fee
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            if addr_to in addresses_state:
                if self.addr_from != addr_to:
                    addresses_state[addr_to].transaction_hashes.append(self.txhash)
                addresses_state[addr_to].tokens[bin2hstr(self.token_txhash).encode()] += amount

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].tokens[bin2hstr(self.token_txhash).encode()] += self.total_amount
            addresses_state[self.addr_from].balance += self.fee
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            if addr_to in addresses_state:
                if self.addr_from != addr_to:
                    addresses_state[addr_to].transaction_hashes.remove(self.txhash)
                addresses_state[addr_to].tokens[bin2hstr(self.token_txhash).encode()] -= amount

        self._revert_state_changes_for_PK(addresses_state, state)

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        for addr_to in self.addrs_to:
            addresses_set.add(addr_to)


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
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False))

        for index in range(0, len(self.slave_pks)):
            tmptxhash = (tmptxhash +
                         self.slave_pks[index] +
                         self.access_types[index].to_bytes(8, byteorder='big', signed=False))

        return sha256(tmptxhash)

    @staticmethod
    def create(slave_pks: list, access_types: list, fee: int, xmss_pk: bytes, master_addr: bytes = None):
        transaction = SlaveTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        for slave_pk in slave_pks:
            transaction._data.slave.slave_pks.append(slave_pk)
        for access_type in access_types:
            transaction._data.slave.access_types.append(access_type)
        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk

        return transaction

    def _validate_custom(self) -> bool:
        if (len(self.slave_pks) > config.dev.transaction_multi_output_limit or
                len(self.access_types) > config.dev.transaction_multi_output_limit):
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

    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState) -> bool:
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('Slave: State validation failed for %s because: Negative send', bin2hstr(self.txhash))
            return False

        if tx_balance < self.fee:
            logger.info('Slave: State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('Slave: State validation failed for %s because: OTS Public key re-use detected', bin2hstr(self.txhash))
            return False

        return True

    def apply_state_changes(self, addresses_state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= self.fee
            for index in range(0, len(self.slave_pks)):
                addresses_state[self.addr_from].add_slave_pks_access_type(self.slave_pks[index],
                                                                          self.access_types[index])
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            for index in range(0, len(self.slave_pks)):
                addresses_state[self.addr_from].remove_slave_pks_access_type(self.slave_pks[index])
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, state)


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
