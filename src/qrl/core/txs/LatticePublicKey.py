from pyqrllib.pyqrllib import bin2hstr

from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.misc import sha256


class LatticePublicKey(Transaction):
    """
    LatticePublicKey transaction to store the public key.
    This transaction has been designed for Ephemeral Messaging.
    """

    def __init__(self, protobuf_transaction=None):
        super(LatticePublicKey, self).__init__(protobuf_transaction)

    @property
    def kyber_pk(self):
        return self._data.latticePK.kyber_pk

    @property
    def dilithium_pk(self):
        return self._data.latticePK.dilithium_pk

    def get_hashable_bytes(self):
        return sha256(
            self.master_addr +
            self.fee.to_bytes(8, byteorder='big', signed=False) +
            self.kyber_pk +
            self.dilithium_pk
        )

    @staticmethod
    def create(fee, kyber_pk, dilithium_pk, xmss_pk, master_addr: bytes = None):
        transaction = LatticePublicKey()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.fee = fee
        transaction._data.public_key = xmss_pk

        transaction._data.latticePK.kyber_pk = bytes(kyber_pk)
        transaction._data.latticePK.dilithium_pk = bytes(dilithium_pk)

        return transaction

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        tx_balance = addr_from_state.balance

        if self.fee < 0:
            logger.info('Lattice Txn: State validation failed %s : Negative fee %s', bin2hstr(self.txhash), self.fee)
            return False

        if tx_balance < self.fee:
            logger.info('Lattice Txn: State validation failed %s : Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, fee: %s', tx_balance, self.fee)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('Lattice Txn: OTS Public key re-use detected %s', bin2hstr(self.txhash))
            return False

        return True

    def _validate_custom(self):
        # FIXME: This is missing
        return True

    def apply_state_changes(self, addresses_state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= self.fee
            addresses_state[self.addr_from].add_lattice_pk(self)
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, state):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += self.fee
            addresses_state[self.addr_from].remove_lattice_pk(self)
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, state)
