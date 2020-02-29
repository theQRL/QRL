from pyqrllib.pyqrllib import bin2hstr, QRLHelper
from typing import Union

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


class MessageTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(MessageTransaction, self).__init__(protobuf_transaction)

    @property
    def message_hash(self):
        return self._data.message.message_hash

    @property
    def addr_to(self):
        return self._data.message.addr_to

    def get_data_bytes(self):
        return self.master_addr + \
               self.fee.to_bytes(8, byteorder='big', signed=False) + \
               self.message_hash + \
               self.addr_to

    @staticmethod
    def create(message_hash: bytes, addr_to: Union[bytes, None], fee: int, xmss_pk: bytes, master_addr: bytes = None):
        transaction = MessageTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.message.message_hash = message_hash
        if addr_to:
            transaction._data.message.addr_to = addr_to

        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def _validate_custom(self) -> bool:
        if len(self.message_hash) == 0:
            logger.warning('Message cannot be empty')
            return False

        if len(self.addr_to) > 0 and not (OptimizedAddressState.address_is_valid(self.addr_to)):
            logger.warning('[MessageTransaction] Invalid address addr_to: %s', bin2hstr(self.addr_to))
            return False

        if self.fee < 0:
            logger.info('State validation failed for %s because: Negative send', bin2hstr(self.txhash))
            return False

        return True

    def _validate_extended(self, state_container: StateContainer) -> bool:
        if len(self.addr_to) != 0:
            if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
                logger.warning("[MessageTransaction] Hard Fork Feature not yet activated")
                return False

        if len(self.message_hash) > state_container.current_dev_config.message_max_length:  # TODO: Move to dev config
            logger.warning('Message length cannot be more than %s', state_container.current_dev_config.message_max_length)
            logger.warning('Found message length %s', len(self.message_hash))
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance

        if tx_balance < self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        if self.addr_to:
            addresses_set.add(self.addr_to)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        if self.addr_to:
            addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
            address_state = state_container.addresses_state[self.addr_to]
            if self.addr_to not in (self.addr_from, addr_from_pk):
                state_container.paginated_tx_hash.insert(address_state, self.txhash)
                state_container.paginated_inbox_message.insert(address_state, self.txhash)

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        if self.addr_to:
            addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
            address_state = state_container.addresses_state[self.addr_to]
            if self.addr_to not in (self.addr_from, addr_from_pk):
                state_container.paginated_tx_hash.remove(address_state, self.txhash)
                state_container.paginated_inbox_message.remove(address_state, self.txhash)

        return self._revert_state_changes_for_PK(state_container)
