from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


class SlaveTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(SlaveTransaction, self).__init__(protobuf_transaction)

    @property
    def slave_pks(self):
        return self._data.slave.slave_pks

    @property
    def access_types(self):
        return self._data.slave.access_types

    def get_data_bytes(self) -> bytes:
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False))

        for index in range(0, len(self.slave_pks)):
            tmptxhash = (tmptxhash +
                         self.slave_pks[index] +
                         self.access_types[index].to_bytes(8, byteorder='big', signed=False))

        return tmptxhash

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

        transaction.validate_or_raise(verify_signature=False)

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
            logger.info('Slave: State validation failed for %s because: OTS Public key re-use detected',
                        bin2hstr(self.txhash))
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

    def revert_state_changes(self, addresses_state, chain_manager):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            for index in range(0, len(self.slave_pks)):
                addresses_state[self.addr_from].remove_slave_pks_access_type(self.slave_pks[index])
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, chain_manager)
