from pyqrllib.pyqrllib import QRLHelper, bin2hstr

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.misc import sha256


class MultiSigCreate(Transaction):
    """
    MultiSigCreate for the creation of multi sig wallet.
    """

    def __init__(self, protobuf_transaction=None):
        super(MultiSigCreate, self).__init__(protobuf_transaction)

    @property
    def signatories(self):
        return self._data.multi_sig_create.signatories

    @property
    def weights(self):
        return self._data.multi_sig_create.weights

    @property
    def total_weight(self):
        total_weight = 0
        for weight in self.weights:
            total_weight += weight
        return total_weight

    @property
    def threshold(self):
        return self._data.multi_sig_create.threshold

    def get_data_hash(self):
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False) +
                     self.threshold.to_bytes(8, byteorder='big', signed=False))

        for index in range(0, len(self.signatories)):
            tmptxhash = (tmptxhash +
                         self.signatories[index] +
                         self.weights[index].to_bytes(8, byteorder='big', signed=False))

        return sha256(tmptxhash)

    @staticmethod
    def create(signatories: list, weights: list, threshold: int, fee, xmss_pk, master_addr: bytes = None):
        multi_sig_create = MultiSigCreate()

        if master_addr:
            multi_sig_create._data.master_addr = master_addr

        multi_sig_create._data.public_key = bytes(xmss_pk)

        for signatory in signatories:
            multi_sig_create._data.multi_sig_create.signatories.append(signatory)

        for weight in weights:
            multi_sig_create._data.multi_sig_create.weights.append(weight)

        multi_sig_create._data.multi_sig_create.threshold = threshold
        multi_sig_create._data.fee = int(fee)

        multi_sig_create.validate_or_raise(verify_signature=False)

        return multi_sig_create

    def _validate_custom(self):
        if len(self.signatories) == 0:
            logger.warning("[MultiSigCreate] No Signatories found")
            return False

        for weight in self.weights:
            if weight == 0:
                logger.warning('Weight cannot be 0 - %s', weight)
                logger.warning('Invalid MultiSigCreate Transaction')
                return False

        if self.fee < 0:
            logger.warning('MultiSigCreate [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)
            return False

        if self.total_weight < self.threshold:
            logger.warning('[MultiSigCreate] Validation failed for %s because: Insufficient weight',
                           bin2hstr(self.txhash))
            logger.warning('Total weight: %s, Threshold: %s', self.total_weight, self.threshold)
            return False

        if len(set(self.signatories)) != len(self.signatories):
            logger.warning('[MultiSigCreate] Signatories list include duplicate signatories')
            return False

        if len(self.signatories) != len(self.weights):
            logger.warning('[MultiSigCreate] Mismatch number of signatories & weights')
            logger.warning('>> Length of signatories %s', len(self.signatories))
            logger.warning('>> Length of weights %s', len(self.weights))
            return False

        if not OptimizedAddressState.address_is_valid(self.addr_from):
            logger.warning('[MultiSigCreate] Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        for signatory in self.signatories:
            if not OptimizedAddressState.address_is_valid(signatory):
                logger.warning('[MultiSigCreate] Invalid address addr_to: %s', bin2hstr(signatory))
                return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def _validate_extended(self, state_container: StateContainer):
        if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
            logger.warning("[MultiSigCreate] Hard Fork Feature not yet activated")
            return False

        if len(self.signatories) > state_container.current_dev_config.transaction_multi_output_limit:
            logger.warning('[MultiSigCreate] Number of signatories exceeds max limit')
            logger.warning('Number of Signatories %s', len(self.signatories))
            logger.warning('Number of Weights %s', len(self.weights))
            return False

        tx_balance = state_container.addresses_state[self.addr_from].balance

        if tx_balance < self.fee:
            logger.info('State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, fee: %s, amount: %s', tx_balance, self.fee)
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        for signatory in self.signatories:
            addresses_set.add(signatory)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        multi_sig_address_state = MultiSigAddressState.get_default(self.txhash,
                                                                   self.signatories,
                                                                   self.weights,
                                                                   self.threshold)
        state_container.addresses_state[multi_sig_address_state.address] = multi_sig_address_state
        state_container.paginated_tx_hash.insert(multi_sig_address_state, self.txhash)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        for index in range(0, len(self.signatories)):
            signatory = self.signatories[index]
            address_state = state_container.addresses_state[signatory]
            if signatory not in (self.addr_from, addr_from_pk):
                state_container.paginated_tx_hash.insert(address_state, self.txhash)
            state_container.paginated_multisig_address.insert(address_state, multi_sig_address_state.address)

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        multi_sig_address = MultiSigAddressState.generate_multi_sig_address(self.txhash)
        MultiSigAddressState.remove_multi_sig_address_state(state, multi_sig_address, state_container.batch)

        addr_from_pk = bytes(QRLHelper.getAddress(self.PK))
        for index in range(0, len(self.signatories)):
            signatory = self.signatories[index]
            address_state = state_container.addresses_state[signatory]
            if signatory not in (self.addr_from, addr_from_pk):
                state_container.paginated_tx_hash.remove(address_state, self.txhash)
            state_container.paginated_multisig_address.remove(address_state, multi_sig_address)

        if multi_sig_address in state_container.addresses_state:
            del state_container.addresses_state[multi_sig_address]

        return self._revert_state_changes_for_PK(state_container)
