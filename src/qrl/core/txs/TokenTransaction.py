from pyqrllib.pyqrllib import bin2hstr, QRLHelper

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


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

    def get_data_bytes(self):
        data_bytes = (self.master_addr +
                      self.fee.to_bytes(8, byteorder='big', signed=False) +
                      self.symbol +
                      self.name +
                      self.owner +
                      self._data.token.decimals.to_bytes(8, byteorder='big', signed=False))

        for initial_balance in self._data.token.initial_balances:
            data_bytes += initial_balance.address
            data_bytes += initial_balance.amount.to_bytes(8, byteorder='big', signed=False)

        return data_bytes

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

        transaction.validate_or_raise(verify_signature=False)

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
            if initial_balance.amount <= 0:
                logger.warning('Invalid Initial Amount in Token Transaction')
                logger.warning('Address %s | Amount %s', initial_balance.address, initial_balance.amount)
                return False

        allowed_decimals = self.calc_allowed_decimals(sum_of_initial_balances // 10 ** self.decimals)

        if self.decimals > allowed_decimals:
            logger.warning('Decimal is greater than maximum allowed decimal')
            logger.warning('Allowed Decimal %s', allowed_decimals)
            logger.warning('Decimals Found %s', self.decimals)
            return False

        if self.fee < 0:
            raise ValueError('TokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if not AddressState.address_is_valid(self.addr_from):
            logger.warning('Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        if not AddressState.address_is_valid(self.owner):
            logger.warning('Invalid address owner_addr: %s', bin2hstr(self.owner))
            return False

        for address_balance in self.initial_balances:
            if not AddressState.address_is_valid(address_balance.address):
                logger.warning('Invalid address in initial_balances: %s', bin2hstr(address_balance.address))
                return False

        if tx_balance < self.fee:
            logger.info('TokenTxn State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('TokenTxn State validation failed for %s because: OTS Public key re-use detected',
                        bin2hstr(self.txhash))
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
                addresses_state[initial_balance.address].update_token_balance(self.txhash, initial_balance.amount)
                addresses_state[initial_balance.address].transaction_hashes.append(self.txhash)

        if self.owner in addresses_state and not owner_processed:
            addresses_state[self.owner].transaction_hashes.append(self.txhash)

        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= self.fee
            if not addr_from_processed and self.addr_from != self.owner:
                addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        if addr_from_pk in addresses_state:
            if self.addr_from != addr_from_pk and addr_from_pk != self.owner:
                if not addr_from_pk_processed:
                    addresses_state[addr_from_pk].transaction_hashes.append(self.txhash)
            addresses_state[addr_from_pk].increase_nonce()
            addresses_state[addr_from_pk].set_ots_key(self.ots_key)

    def revert_state_changes(self, addresses_state, chain_manager):
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
                addresses_state[initial_balance.address].update_token_balance(self.txhash,
                                                                              initial_balance.amount * -1)
                addresses_state[initial_balance.address].transaction_hashes.remove(self.txhash)

        if self.owner in addresses_state and not owner_processed:
            addresses_state[self.owner].transaction_hashes.remove(self.txhash)

        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            if not addr_from_processed and self.addr_from != self.owner:
                addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        if addr_from_pk in addresses_state:
            if self.addr_from != addr_from_pk and addr_from_pk != self.owner:
                if not addr_from_pk_processed:
                    addresses_state[addr_from_pk].transaction_hashes.remove(self.txhash)
            addresses_state[addr_from_pk].decrease_nonce()
            addresses_state[addr_from_pk].unset_ots_key(self.ots_key, chain_manager)

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        addresses_set.add(self.owner)
        for initial_balance in self.initial_balances:
            addresses_set.add(initial_balance.address)
