from pyqrllib.pyqrllib import bin2hstr

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.VoteStats import VoteStats
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.misc import sha256


class MultiSigSpend(Transaction):
    """
    MultiSigSpend for the transaction of QRL from a multi sig wallet to another wallet.
    """

    def __init__(self, protobuf_transaction=None):
        super(MultiSigSpend, self).__init__(protobuf_transaction)

    @property
    def multi_sig_address(self):
        return self._data.multi_sig_spend.multi_sig_address

    @property
    def addrs_to(self):
        return self._data.multi_sig_spend.addrs_to

    @property
    def total_amount(self):
        total_amount = 0
        for amount in self.amounts:
            total_amount += amount
        return total_amount

    @property
    def amounts(self):
        return self._data.multi_sig_spend.amounts

    @property
    def expiry_block_number(self):
        return self._data.multi_sig_spend.expiry_block_number

    def get_data_hash(self):
        tmp_tx_hash = (self.master_addr +
                       self.fee.to_bytes(8, byteorder='big', signed=False) +
                       self.multi_sig_address +
                       self.expiry_block_number.to_bytes(8, byteorder='big', signed=False))

        for index in range(0, len(self.addrs_to)):
            tmp_tx_hash = (tmp_tx_hash +
                           self.addrs_to[index] +
                           self.amounts[index].to_bytes(8, byteorder='big', signed=False))

        return sha256(tmp_tx_hash)

    @staticmethod
    def create(multi_sig_address: bytes,
               addrs_to: list,
               amounts: list,
               expiry_block_number: int,
               fee: int,
               xmss_pk,
               master_addr: bytes = None):
        multi_sig_spend = MultiSigSpend()

        if master_addr:
            multi_sig_spend._data.master_addr = master_addr

        multi_sig_spend._data.public_key = bytes(xmss_pk)

        multi_sig_spend._data.multi_sig_spend.multi_sig_address = multi_sig_address

        for addr_to in addrs_to:
            multi_sig_spend._data.multi_sig_spend.addrs_to.append(addr_to)

        for amount in amounts:
            multi_sig_spend._data.multi_sig_spend.amounts.append(amount)

        multi_sig_spend._data.multi_sig_spend.expiry_block_number = expiry_block_number

        multi_sig_spend._data.fee = int(fee)

        multi_sig_spend.validate_or_raise(verify_signature=False)

        return multi_sig_spend

    def _validate_custom(self):
        for amount in self.amounts:
            if amount == 0:
                logger.warning('Amount cannot be 0 - %s', self.amounts)
                logger.warning('Invalid TransferTransaction')
                return False

        if self.fee < 0:
            logger.warning('MultiSigSpend [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)
            return False

        if len(self.addrs_to) == 0:
            logger.warning('[MultiSigSpend] No addrs_to found')
            return False

        if len(self.addrs_to) != len(self.amounts):
            logger.warning('[MultiSigSpend] Mismatch number of addresses to & amounts')
            logger.warning('>> Length of addrs_to %s', len(self.addrs_to))
            logger.warning('>> Length of amounts %s', len(self.amounts))
            return False

        if not MultiSigAddressState.address_is_valid(self.multi_sig_address):
            logger.warning('[MultiSigSpend] Invalid MultiSig Address')
            logger.warning('Multi Sig Address %s', self.multi_sig_address)
            return False

        if not OptimizedAddressState.address_is_valid(self.addr_from):
            logger.warning('[MultiSigSpend] Invalid address addr_from: %s', bin2hstr(self.addr_from))
            return False

        for addr_to in self.addrs_to:
            if not (OptimizedAddressState.address_is_valid(addr_to) or MultiSigAddressState.address_is_valid(addr_to)):
                logger.warning('[MultiSigSpend] Invalid address addr_to: %s', bin2hstr(addr_to))
                return False

        return True

    def _validate_extended(self, state_container: StateContainer):
        if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
            logger.warning("[MultiSigSpend] Hard Fork Feature not yet activated")
            return False

        if len(self.addrs_to) > state_container.current_dev_config.transaction_multi_output_limit:
            logger.warning('[MultiSigSpend] Number of addresses exceeds max limit')
            logger.warning('Number of addresses %s', len(self.addrs_to))
            logger.warning('Number of amounts %s', len(self.amounts))
            return False

        addr_from_state = state_container.addresses_state[self.addr_from]
        if self.multi_sig_address not in state_container.addresses_state:
            logger.error("[MultiSigSpend] Multi Sig address state not found in state_container %s",
                         self.multi_sig_address)
            return False

        multi_sig_address_state = state_container.addresses_state[self.multi_sig_address]
        block_number = state_container.block_number

        if addr_from_state.address != self.addr_from:
            logger.error("[MultiSigSpend] Unexpected addr_from_state")
            logger.error("Expecting State for address %s, but got state for address %s",
                         bin2hstr(self.addr_from),
                         bin2hstr(addr_from_state.address))
            return False

        if multi_sig_address_state.address != self.multi_sig_address:
            logger.error("[MultiSigSpend] Unexpected multi sig address state")
            logger.error("Expecting State for address %s, but got state for address %s",
                         bin2hstr(self.multi_sig_address),
                         bin2hstr(multi_sig_address_state.address))
            return False

        tx_balance = addr_from_state.balance
        total_amount = self.total_amount

        if tx_balance < self.fee:
            logger.info('[MultiSigSpend] State validation failed for %s because: Insufficient funds',
                        bin2hstr(self.txhash))
            logger.info('address: %s, balance: %s, fee: %s', bin2hstr(self.addr_from), tx_balance, self.fee)
            return False

        if multi_sig_address_state.balance < total_amount:
            logger.info('[MultiSigSpend] State validation failed for %s because: Insufficient funds',
                        bin2hstr(self.txhash))
            logger.info('address: %s, balance: %s, fee: %s', bin2hstr(self.multi_sig_address), tx_balance, self.fee)
            return False

        # Multi Sig Spend considered to be expired after block having block number equals to
        # self.expiry_block_number gets added into the main chain
        if self.expiry_block_number <= block_number:
            logger.info('[MultiSigSpend] State validation failed for %s due to invalid expiry_block_number',
                        bin2hstr(self.txhash))
            logger.info('Chain Height: %s, Expiry Block Number: %s',
                        block_number,
                        self.expiry_block_number)
            return False

        if self.addr_from not in multi_sig_address_state.signatories:
            logger.info('[MultiSigSpend] Address is not in the signatories list: %s',
                        bin2hstr(self.addr_from))
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
        addresses_set.add(self.multi_sig_address)
        for addrs_to in self.addrs_to:
            addresses_set.add(addrs_to)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)

        # TODO: Following line might not be needed
        state_container.multi_sig_spend_txs[self.txhash] = self

        multi_sig_address_state = state_container.addresses_state[self.multi_sig_address]
        for signatory_address in multi_sig_address_state.signatories:
            signatory_address_state = state_container.addresses_state[signatory_address]
            state_container.paginated_multi_sig_spend.insert(signatory_address_state, self.txhash)

        state_container.paginated_tx_hash.insert(multi_sig_address_state, self.txhash)
        state_container.paginated_multi_sig_spend.insert(multi_sig_address_state, self.txhash)

        vote_stats = VoteStats.create(self.multi_sig_address,
                                      self.txhash,
                                      state_container.addresses_state[self.multi_sig_address].signatories,
                                      self.expiry_block_number)
        state_container.votes_stats[self.txhash] = vote_stats

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        multi_sig_address_state = state_container.addresses_state[self.multi_sig_address]
        for signatory_address in multi_sig_address_state.signatories:
            signatory_address_state = state_container.addresses_state[signatory_address]
            state_container.paginated_multi_sig_spend.remove(signatory_address_state, self.txhash)

        state_container.paginated_tx_hash.remove(multi_sig_address_state, self.txhash)
        state_container.paginated_multi_sig_spend.remove(multi_sig_address_state, self.txhash)

        VoteStats.delete_state(state, self.txhash, state_container.batch)

        if self.txhash in state_container.votes_stats:
            del state_container.votes_stats[self.txhash]

        return self._revert_state_changes_for_PK(state_container)
