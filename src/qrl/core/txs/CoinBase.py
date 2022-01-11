from pyqrllib.pyqrllib import bin2hstr

from qrl.core.config import DevConfig
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


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

    def get_data_bytes(self):
        # nonce only added to the hashable bytes of CoinBase
        return self.master_addr + \
               self.addr_to + \
               self.nonce.to_bytes(8, byteorder='big', signed=False) + \
               self.amount.to_bytes(8, byteorder='big', signed=False)

    @staticmethod
    def create(dev_config: DevConfig, amount, miner_address, block_number):
        transaction = CoinBase()
        transaction._data.master_addr = dev_config.coinbase_address
        transaction._data.coinbase.addr_to = miner_address
        transaction._data.coinbase.amount = amount
        transaction._data.nonce = block_number + 1
        transaction._data.transaction_hash = transaction.get_data_hash()

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def update_mining_address(self, mining_address: bytes):
        self._data.coinbase.addr_to = mining_address
        self._data.transaction_hash = self.get_data_hash()

    def _coinbase_filter(self):
        pass

    def _get_allowed_access_types(self):
        # FIXME: 0 and 1 are not clear..
        return [0, 1]

    def _get_master_address(self):
        return self.addr_to

    def _validate_custom(self):
        if self.fee != 0:
            logger.warning('Fee for coinbase transaction should be 0')
            return False

        return True

    # noinspection PyBroadException
    # Never change this function name to _validate_extended, to keep difference between other txns &
    # Coinbase txn, will hit unimplemented error in case called for an coinbase txn.
    def _validate_extended(self, state_container: StateContainer):
        dev_config = state_container.current_dev_config
        block_number = state_container.block_number

        if self.master_addr != dev_config.coinbase_address:
            logger.warning('Master address doesnt match with coinbase_address')
            logger.warning('%s %s', bin2hstr(self.master_addr), bin2hstr(dev_config.coinbase_address))
            return False

        if not OptimizedAddressState.address_is_valid(self.addr_to):
            logger.warning('Invalid address addr_from: %s addr_to: %s',
                           bin2hstr(self.master_addr), bin2hstr(self.addr_to))
            return False

        if self.nonce != block_number + 1:
            logger.warning('Nonce %s doesnt match with block_number %s',
                           self.nonce, block_number)
            return False

        return self._validate_custom()

    def set_affected_address(self, addresses_set: set):
        addresses_set.add(self.master_addr)
        addresses_set.add(self.addr_to)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_to]
        address_state.update_balance(state_container, self.amount)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        address_state = state_container.addresses_state[self.master_addr]
        address_state.update_balance(state_container, state_container.block_reward, subtract=True)
        address_state.increase_nonce()
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        return True

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_to]
        address_state.update_balance(state_container, self.amount, subtract=True)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        address_state = state_container.addresses_state[self.master_addr]
        address_state.update_balance(state_container, state_container.block_reward)
        address_state.decrease_nonce()
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        return True
