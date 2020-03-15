from pyqrllib.pyqrllib import bin2hstr

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.generated.qrl_pb2 import TokenBalance


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

    def get_data_bytes(self):
        data_bytes = (self.master_addr +
                      self.fee.to_bytes(8, byteorder='big', signed=False) +
                      self.token_txhash)

        for index in range(0, len(self.addrs_to)):
            data_bytes = (data_bytes +
                          self.addrs_to[index] +
                          self.amounts[index].to_bytes(8, byteorder='big', signed=False))

        return data_bytes

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

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def _validate_custom(self):
        for amount in self.amounts:
            if amount == 0:
                logger.warning('Amount cannot be 0 - %s', self.amounts)
                logger.warning('TransferTokenTransaction')
                return False

        if self.fee < 0:
            logger.info('TransferTokenTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)
            return False

        if len(self.addrs_to) != len(self.amounts):
            logger.warning('[TransferTokenTransaction] Mismatch number of addresses to & amounts')
            logger.warning('>> Length of addresses_to %s', len(self.addrs_to))
            logger.warning('>> Length of amounts %s', len(self.amounts))
            return False

        if not OptimizedAddressState.address_is_valid(self.addr_from):
            logger.warning('[TransferTokenTransaction] Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        for addr_to in self.addrs_to:
            if not OptimizedAddressState.address_is_valid(addr_to):
                logger.warning('[TransferTokenTransaction] Invalid address addr_to: %s', bin2hstr(addr_to))
                return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def _validate_extended(self, state_container: StateContainer):
        if (len(self.addrs_to) > state_container.current_dev_config.transaction_multi_output_limit or
                len(self.amounts) > state_container.current_dev_config.transaction_multi_output_limit):
            logger.warning('[TransferTokenTransaction] Number of addresses or amounts exceeds max limit')
            logger.warning('Number of addresses %s', len(self.addrs_to))
            logger.warning('Number of amounts %s', len(self.amounts))
            return False

        if len(self.addrs_to) == 0:
            logger.warning("[TransferTokenTransaction] No Addrs To found")
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance
        total_amount = self.total_amount
        if self.fee < 0 or total_amount < 0:
            logger.info('[TransferTokenTransaction] State validation failed for %s because: ', bin2hstr(self.txhash))
            logger.info('Txn amount: %s, Fee: %s', total_amount, self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('[TransferTokenTransaction] State validation failed for %s because: Insufficient funds',
                        bin2hstr(self.txhash))
            logger.info('balance: %s, Fee: %s', tx_balance, self.fee)
            return False

        if (self.addr_from, self.token_txhash) not in state_container.tokens.data:
            logger.info('%s doesnt own any such token %s ', bin2hstr(self.addr_from), bin2hstr(self.token_txhash))
            return False

        token_balance = state_container.tokens.data[(self.addr_from, self.token_txhash)]
        if token_balance.balance < total_amount:
            logger.info('Insufficient amount of token')
            logger.info('Token Balance: %s, Sent Token Amount: %s',
                        token_balance.balance,
                        total_amount)
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        for addr_to in self.addrs_to:
            addresses_set.add(addr_to)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        state_container.tokens.data[(self.addr_from, self.token_txhash)].balance -= self.total_amount
        decimals = state_container.tokens.data[(self.addr_from, self.token_txhash)].decimals
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            address_state = state_container.addresses_state[addr_to]

            # If receiver doesn't have this token before, then initialize token balance data into state
            # before adding the new balance.
            if (addr_to, self.token_txhash) not in state_container.tokens.data:
                state_container.tokens.data[(addr_to,
                                             self.token_txhash)] = TokenBalance(balance=0,
                                                                                decimals=decimals,
                                                                                tx_hash=self.txhash,
                                                                                delete=False)
                state_container.paginated_tokens_hash.insert(address_state, self.token_txhash)

            state_container.tokens.data[(addr_to, self.token_txhash)].balance += amount

            if self.addr_from != addr_to:
                state_container.paginated_tx_hash.insert(address_state, self.txhash)

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        for index in range(0, len(self.addrs_to)):
            addr_to = self.addrs_to[index]
            amount = self.amounts[index]
            address_state = state_container.addresses_state[addr_to]
            key = (addr_to, self.token_txhash)

            state_container.tokens.data[key].balance -= amount
            # There is a chance that same address is transmitted with token multiple times,
            # in such a case, to avoid removal of token_txhash from paginated_tokens_hash
            # delete must be checked for false
            if state_container.tokens.data[key].tx_hash == self.txhash and \
                    state_container.tokens.data[key].delete is False:
                state_container.tokens.data[key].delete = True
                state_container.paginated_tokens_hash.remove(address_state, self.token_txhash)

            if self.addr_from != addr_to:
                state_container.paginated_tx_hash.remove(address_state, self.txhash)

        state_container.tokens.data[(self.addr_from, self.token_txhash)].balance += self.total_amount
        state_container.tokens.data[(self.addr_from, self.token_txhash)].delete = False
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        return self._revert_state_changes_for_PK(state_container)
