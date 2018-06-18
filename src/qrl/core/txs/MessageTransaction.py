from pyqrllib.pyqrllib import bin2hstr

from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


class MessageTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(MessageTransaction, self).__init__(protobuf_transaction)

    @property
    def message_hash(self):
        return self._data.message.message_hash

    def get_data_bytes(self):
        return self.master_addr + \
               self.fee.to_bytes(8, byteorder='big', signed=False) + \
               self.message_hash

    @staticmethod
    def create(message_hash: bytes, fee: int, xmss_pk: bytes, master_addr: bytes = None):
        transaction = MessageTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.message.message_hash = message_hash
        transaction._data.fee = fee

        transaction._data.public_key = xmss_pk

        transaction.validate_or_raise(verify_signature=False)

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

    def revert_state_changes(self, addresses_state, chain_manager):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, chain_manager)
