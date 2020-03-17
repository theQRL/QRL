from pyqrllib.pyqrllib import bin2hstr, QRLHelper

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.generated.qrl_pb2 import TokenBalance


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
        if len(self.symbol) == 0:
            logger.warning('Missing Token Symbol')
            return False

        if len(self.name) == 0:
            logger.warning('Missing Token Name')
            return False

        if len(self.initial_balances) == 0:
            logger.warning('Invalid Token Transaction, without any initial balance')
            return False

        if self.decimals > 19:
            logger.warning('Token decimals cannot be more than 19')
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
    def _validate_extended(self, state_container: StateContainer):
        if len(self.symbol) > state_container.current_dev_config.max_token_symbol_length:
            logger.warning('Token Symbol Length exceeds maximum limit')
            logger.warning('Found Symbol Length %s', len(self.symbol))
            logger.warning('Expected Symbol length %s', state_container.current_dev_config.max_token_symbol_length)
            return False

        if len(self.name) > state_container.current_dev_config.max_token_name_length:
            logger.warning('Token Name Length exceeds maximum limit')
            logger.warning('Found Name Length %s', len(self.symbol))
            logger.warning('Expected Name length %s', state_container.current_dev_config.max_token_name_length)
            return False

        if not OptimizedAddressState.address_is_valid(self.addr_from):
            logger.warning('Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance

        if not OptimizedAddressState.address_is_valid(self.owner):
            logger.warning('Invalid address owner_addr: %s', bin2hstr(self.owner))
            return False

        for address_balance in self.initial_balances:
            if not OptimizedAddressState.address_is_valid(address_balance.address):
                logger.warning('Invalid address in initial_balances: %s', bin2hstr(address_balance.address))
                return False

        if tx_balance < self.fee:
            logger.warning('TokenTxn State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.warning('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        addresses_set.add(self.owner)
        for initial_balance in self.initial_balances:
            addresses_set.add(initial_balance.address)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
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

            # If a QRL address has been mentioned multiple times in initial balance
            # then check if that address has already been initialized with some token
            # balance, if found, then add the new balance the already initialized balance
            if (initial_balance.address, self.txhash) in state_container.tokens.data:
                state_container.tokens.data[(initial_balance.address,
                                             self.txhash)].balance += initial_balance.amount
            else:
                state_container.tokens.data[(initial_balance.address,
                                             self.txhash)] = TokenBalance(balance=initial_balance.amount,
                                                                          decimals=self.decimals,
                                                                          tx_hash=self.txhash,
                                                                          delete=False)
            address_state = state_container.addresses_state[initial_balance.address]
            state_container.paginated_tx_hash.insert(address_state, self.txhash)
            state_container.paginated_tokens_hash.insert(address_state, self.txhash)

        if not owner_processed:
            address_state = state_container.addresses_state[self.owner]
            state_container.paginated_tx_hash.insert(address_state, self.txhash)

        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        if not addr_from_processed and self.addr_from != self.owner:
            state_container.paginated_tx_hash.insert(address_state, self.txhash)

        address_state = state_container.addresses_state[addr_from_pk]
        if self.addr_from != addr_from_pk and addr_from_pk != self.owner:
            if not addr_from_pk_processed:
                state_container.paginated_tx_hash.insert(address_state, self.txhash)
        address_state.increase_nonce()
        state_container.paginated_bitfield.set_ots_key(state_container.addresses_state,
                                                       addr_from_pk,
                                                       self.ots_key)

        return True

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
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

            address_state = state_container.addresses_state[initial_balance.address]
            state_container.tokens.data[(initial_balance.address, self.txhash)] = TokenBalance(balance=0,
                                                                                               delete=True)
            state_container.paginated_tx_hash.remove(address_state, self.txhash)
            state_container.paginated_tokens_hash.remove(address_state, self.txhash)

        if not owner_processed:
            address_state = state_container.addresses_state[self.owner]
            state_container.paginated_tx_hash.remove(address_state, self.txhash)

        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        if not addr_from_processed and self.addr_from != self.owner:
            state_container.paginated_tx_hash.remove(address_state, self.txhash)

        address_state = state_container.addresses_state[addr_from_pk]
        if self.addr_from != addr_from_pk and addr_from_pk != self.owner:
            if not addr_from_pk_processed:
                state_container.paginated_tx_hash.remove(address_state, self.txhash)
        address_state.decrease_nonce()
        state_container.paginated_bitfield.unset_ots_key(state_container.addresses_state, addr_from_pk, self.ots_key)

        return True
