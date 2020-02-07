from pyqrllib.pyqrllib import bin2hstr, QRLHelper
from typing import Union

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


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

    @property
    def message_data(self):
        return self._data.transfer.message_data

    def get_data_bytes(self):
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False) +
                     self.message_data)

        for index in range(0, len(self.addrs_to)):
            tmptxhash = (tmptxhash +
                         self.addrs_to[index] +
                         self.amounts[index].to_bytes(8, byteorder='big', signed=False))

        return tmptxhash

    @staticmethod
    def create(addrs_to: list, amounts: list, message_data: Union[bytes, None], fee: int, xmss_pk, master_addr: bytes = None):
        transaction = TransferTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.public_key = bytes(xmss_pk)

        for addr_to in addrs_to:
            transaction._data.transfer.addrs_to.append(addr_to)

        for amount in amounts:
            transaction._data.transfer.amounts.append(amount)

        if message_data:
            transaction._data.transfer.message_data = message_data

        transaction._data.fee = int(fee)  # FIXME: Review conversions for quantities

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def _validate_custom(self):
        for amount in self.amounts:
            if amount == 0:
                logger.warning('Amount cannot be 0 - %s', self.amounts)
                logger.warning('Invalid TransferTransaction')
                return False

        if self.fee < 0:
            logger.info('TransferTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)
            return False

        if len(self.addrs_to) == 0:
            logger.warning("[TransferTransaction] No Addrs To found")
            return False

        if len(self.addrs_to) != len(self.amounts):
            logger.warning('[TransferTransaction] Mismatch number of addresses to & amounts')
            logger.warning('>> Length of addresses_to %s', len(self.addrs_to))
            logger.warning('>> Length of amounts %s', len(self.amounts))
            return False

        if not OptimizedAddressState.address_is_valid(self.addr_from):
            logger.warning('[TransferTransaction] Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        for addr_to in self.addrs_to:
            if not (OptimizedAddressState.address_is_valid(addr_to) or MultiSigAddressState.address_is_valid(addr_to)):
                logger.warning('[TransferTransaction] Invalid address addr_to: %s', bin2hstr(addr_to))
                return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def _validate_extended(self, state_container: StateContainer):
        if len(self.message_data) > 0:
            if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
                logger.warning("[TransferTransaction] Hard Fork Feature not yet activated")
                return False

        if len(self.addrs_to) > state_container.current_dev_config.transaction_multi_output_limit:
            logger.warning('[TransferTransaction] Number of addresses exceeds max limit')
            logger.warning('Number of addresses %s', len(self.addrs_to))
            logger.warning('Number of amounts %s', len(self.amounts))
            return False

        if len(self.message_data) > state_container.current_dev_config.message_max_length:
            logger.warning("[TransferTransaction] Message data is greater than message max length limit")
            logger.warning("Message data length %s", len(self.message_data))
            logger.warning("Message data length limit %s", state_container.current_dev_config.message_max_length)
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance
        total_amount = self.total_amount

        for addr_to in self.addrs_to:
            if MultiSigAddressState.address_is_valid(addr_to):
                if addr_to not in state_container.addresses_state:
                    logger.warning('[TransferTransaction] Multi Sig Address doesnt exist: %s', bin2hstr(addr_to))
                    return False

        if tx_balance < total_amount + self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, fee: %s, amount: %s', tx_balance, self.fee, total_amount)
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        for addr_to in self.addrs_to:
            addresses_set.add(addr_to)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.total_amount + self.fee, subtract=True)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            address_state = state_container.addresses_state[addr_to]
            address_state.update_balance(state_container, amount)
            if addr_to in (self.addr_from, addr_from_pk):
                continue
            state_container.paginated_tx_hash.insert(address_state, self.txhash)

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container,
                                     self.total_amount + self.fee)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            address_state = state_container.addresses_state[addr_to]
            address_state.update_balance(state_container, amount, subtract=True)
            if addr_to in (self.addr_from, addr_from_pk):
                continue
            state_container.paginated_tx_hash.remove(address_state, self.txhash)

        return self._revert_state_changes_for_PK(state_container)
