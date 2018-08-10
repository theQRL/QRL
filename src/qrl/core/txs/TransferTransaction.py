from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.misc import sha256


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

    def get_data_hash(self):
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

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def _validate_custom(self):
        for amount in self.amounts:
            if amount == 0:
                logger.warning('Amount cannot be 0 - %s', self.amounts)
                logger.warning('Invalid TransferTransaction')
                return False

        if self.fee < 0:
            raise ValueError('TransferTransaction [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        if len(self.addrs_to) > config.dev.transaction_multi_output_limit:
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
            logger.warning('[TransferTransaction] Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        for addr_to in self.addrs_to:
            if not AddressState.address_is_valid(addr_to):
                logger.warning('[TransferTransaction] Invalid address addr_to: %s', bin2hstr(addr_to))
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

    def apply_state_changes(self, addresses_state: dict):
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

    def revert_state_changes(self, addresses_state, chain_manager):
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

        self._revert_state_changes_for_PK(addresses_state, chain_manager)

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        for addr_to in self.addrs_to:
            addresses_set.add(addr_to)
