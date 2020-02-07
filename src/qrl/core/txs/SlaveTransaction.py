from pyqrllib.pyqrllib import bin2hstr

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.generated.qrl_pb2 import SlaveMetadata


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
        if len(self.slave_pks) != len(self.access_types):
            logger.warning('Number of slave pks are not equal to the number of access types provided')
            logger.warning('Slave pks len %s', len(self.slave_pks))
            logger.warning('Access types len %s', len(self.access_types))
            return False

        if len(set(self.slave_pks)) != len(self.slave_pks):
            logger.warning('Duplicate Slave PKS found')
            logger.warning('Unique Slave pks len %s', len(set(self.slave_pks)))
            logger.warning('Slave pks len %s', len(self.slave_pks))
            return False

        for access_type in self.access_types:
            if access_type not in [0, 1]:
                logger.warning('Invalid Access type %s', access_type)
                return False

        if self.fee < 0:
            logger.info('Slave: State validation failed for %s because: Negative send', bin2hstr(self.txhash))
            return False

        return True

    def _validate_extended(self, state_container: StateContainer) -> bool:
        if (len(self.slave_pks) > state_container.current_dev_config.transaction_multi_output_limit or
                len(self.access_types) > state_container.current_dev_config.transaction_multi_output_limit):
            logger.warning('List has more than %s slave pks or access_types',
                           state_container.current_dev_config.transaction_multi_output_limit)
            logger.warning('Slave pks len %s', len(self.slave_pks))
            logger.warning('Access types len %s', len(self.access_types))
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance

        if tx_balance < self.fee:
            logger.info('Slave: State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        for i in range(len(self.slave_pks)):
            slave_pk = self.slave_pks[i]
            if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
                if len(slave_pk) > state_container.current_dev_config.slave_pk_max_length:
                    logger.info("[Slave Transaction] Slave PK length is beyond limit")
                    return False
            if (self.addr_from, slave_pk) in state_container.slaves.data:
                logger.info("[Slave Transaction] Invalid slave transaction as %s is already a slave for this address",
                            slave_pk)
                return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        for idx in range(0, len(self.slave_pks)):
            state_container.slaves.data[(self.addr_from,
                                         self.slave_pks[idx])] = SlaveMetadata(access_type=self.access_types[idx],
                                                                               tx_hash=self.txhash)
        state_container.paginated_slaves_hash.insert(address_state, self.txhash)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        for idx in range(0, len(self.slave_pks)):
            state_container.slaves.data[(self.addr_from,
                                         self.slave_pks[idx])] = SlaveMetadata(access_type=self.access_types[idx],
                                                                               tx_hash=self.txhash,
                                                                               delete=True)
        state_container.paginated_slaves_hash.remove(address_state, self.txhash)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        return self._revert_state_changes_for_PK(state_container)
