from pyqrllib.pyqrllib import bin2hstr

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.generated.qrl_pb2 import LatticePKMetadata


class LatticeTransaction(Transaction):

    def __init__(self, protobuf_transaction=None):
        super(LatticeTransaction, self).__init__(protobuf_transaction)

    @property
    def pk1(self):  # kyber_pk
        return self._data.latticePK.pk1

    @property
    def pk2(self):  # dilithium_pk
        return self._data.latticePK.pk2

    @property
    def pk3(self):  # ecdsa_pk
        return self._data.latticePK.pk3

    def get_data_bytes(self):
        return self.master_addr + \
               self.fee.to_bytes(8, byteorder='big', signed=False) + \
               self.pk1 + \
               self.pk2 + \
               self.pk3

    @staticmethod
    def create(pk1: bytes, pk2: bytes, pk3: bytes, fee: int, xmss_pk: bytes, master_addr: bytes = None):
        transaction = LatticeTransaction()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.fee = fee
        transaction._data.public_key = xmss_pk

        transaction._data.latticePK.pk1 = bytes(pk1)
        transaction._data.latticePK.pk2 = bytes(pk2)
        transaction._data.latticePK.pk3 = bytes(pk3)

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def _validate_custom(self) -> bool:
        if self.fee < 0:
            logger.info('State validation failed for %s because: Negative send', bin2hstr(self.txhash))
            return False

        return True

    def _validate_extended(self, state_container: StateContainer) -> bool:
        if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
            logger.warning("[LatticeTransaction] Hard Fork Feature not yet activated")
            return False

        dev_config = state_container.current_dev_config
        if len(self.pk1) > dev_config.lattice_pk1_max_length:  # TODO: to fix kyber pk value
            logger.warning('Kyber PK length cannot be more than %s bytes', dev_config.lattice_pk1_max_length)
            logger.warning('Found length %s', len(self.pk1))
            return False

        if len(self.pk2) > dev_config.lattice_pk2_max_length:  # TODO: to fix dilithium pk value
            logger.warning('Dilithium PK length cannot be more than %s bytes', dev_config.lattice_pk2_max_length)
            logger.warning('Found length %s', len(self.pk2))
            return False

        if len(self.pk3) > dev_config.lattice_pk3_max_length:  # TODO: to fix ecdsa pk value
            logger.warning('ECDSA PK length cannot be more than %s bytes', dev_config.lattice_pk3_max_length)
            logger.warning('Found length %s', len(self.pk3))
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance

        if tx_balance < self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, amount: %s', tx_balance, self.fee)
            return False

        if (self.addr_from, self.pk1, self.pk2, self.pk3) in state_container.lattice_pk.data:
            logger.info('State validation failed for %s because: Lattice PKs already exists for this address',
                        bin2hstr(self.txhash))
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        state_container.paginated_lattice_pk.insert(address_state, self.txhash)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        state_container.lattice_pk.data[(self.addr_from,
                                         self.pk1, self.pk2, self.pk3)] = LatticePKMetadata(enabled=True)

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        state_container.paginated_lattice_pk.remove(address_state, self.txhash)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        state_container.lattice_pk.data[(self.addr_from,
                                         self.pk1, self.pk2, self.pk3)] = LatticePKMetadata(enabled=False,
                                                                                            delete=True)

        return self._revert_state_changes_for_PK(state_container)
