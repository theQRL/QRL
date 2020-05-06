from pyqrllib.pyqrllib import bin2hstr

from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.misc import sha256


class MultiSigVote(Transaction):
    """
    MultiSigSpend for the transaction of QRL from a multi sig wallet to another wallet.
    """

    def __init__(self, protobuf_transaction=None):
        super(MultiSigVote, self).__init__(protobuf_transaction)

    @property
    def shared_key(self):
        return self._data.multi_sig_vote.shared_key

    @property
    def unvote(self):
        return self._data.multi_sig_vote.unvote

    @property
    def prev_tx_hash(self):
        return self._data.multi_sig_vote.prev_tx_hash

    def set_prev_tx_hash(self, prev_tx_hash: bytes):
        self._data.multi_sig_vote.prev_tx_hash = prev_tx_hash

    def get_data_hash(self):
        tmp_tx_hash = (self.master_addr +
                       self.fee.to_bytes(8, byteorder='big', signed=False) +
                       self.shared_key +
                       self.unvote.to_bytes(1, byteorder='big', signed=False))

        return sha256(tmp_tx_hash)

    @staticmethod
    def create(shared_key: bytes,
               unvote: bool,
               fee: int,
               xmss_pk,
               master_addr: bytes = None):
        multi_sig_vote = MultiSigVote()

        if master_addr:
            multi_sig_vote._data.master_addr = master_addr

        multi_sig_vote._data.public_key = bytes(xmss_pk)

        multi_sig_vote._data.multi_sig_vote.shared_key = shared_key
        multi_sig_vote._data.multi_sig_vote.unvote = unvote

        multi_sig_vote._data.fee = int(fee)

        multi_sig_vote.validate_or_raise(verify_signature=False)

        return multi_sig_vote

    def _validate_custom(self):
        if self.fee < 0:
            logger.warning('MultiSigVote [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)
            return False

        return True

    def _validate_extended(self, state_container: StateContainer):
        if state_container.block_number < state_container.current_dev_config.hard_fork_heights[0]:
            logger.warning("[MultiSigVote] Hard Fork Feature not yet activated")
            return False

        addr_from_state = state_container.addresses_state[self.addr_from]
        vote_stats = state_container.votes_stats[self.shared_key]
        if vote_stats is None:
            logger.warning("[MultiSigVote] Invalid Shared key %s", bin2hstr(self.shared_key))
            return False
        multi_sig_spend_tx = state_container.multi_sig_spend_txs[self.shared_key]
        block_number = state_container.block_number
        if vote_stats.executed:
            logger.warning("[MultiSigVote] Invalid Tx as MultiSigSpend has already been executed")
            return False

        if multi_sig_spend_tx is None:
            logger.warning("MultiSigSpend not found, Shared Key %s", bin2hstr(self.shared_key))
            return False

        if block_number > multi_sig_spend_tx.expiry_block_number:
            logger.warning("[MultiSigVote] Voted for expired Multi Sig Spend Txn")
            logger.warning("Expiry Block Number: %s, Current Block Number: %s",
                           multi_sig_spend_tx.expiry_block_number,
                           block_number)
            return False

        if self.addr_from not in vote_stats.signatories:
            logger.warning("Address not found in signatory list")
            logger.warning("Address %s, Shared Key %s, Multi Sig Address %s",
                           bin2hstr(self.addr_from),
                           bin2hstr(self.shared_key),
                           bin2hstr(vote_stats.multi_sig_address))
            return False

        index = vote_stats.get_address_index(self.addr_from)
        if vote_stats.unvotes[index] == self.unvote:
            logger.warning("[MultiSigVote] Invalid as Vote type already executed")
            logger.warning("Vote type %s", self.unvote)
            return False

        tx_balance = addr_from_state.balance

        if tx_balance < self.fee:
            logger.warning('[MultiSigVote] State validation failed for %s because: Insufficient funds',
                           bin2hstr(self.txhash))
            logger.warning('balance: %s, fee: %s', tx_balance, self.fee)
            return False

        return True

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)

    def apply(self,
              state: State,
              state_container: StateContainer) -> bool:
        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee, subtract=True)
        state_container.paginated_tx_hash.insert(address_state, self.txhash)
        vote_stats = state_container.votes_stats[self.shared_key]
        multi_sig_address = vote_stats.multi_sig_address

        weight, found = state_container.addresses_state[multi_sig_address].get_weight_by_signatory(self.addr_from)
        if not found:
            logger.info("[MultiSigVote] Address is not the signatory for the multi sig address")
            return False

        self.set_prev_tx_hash(vote_stats.get_vote_tx_hash_by_signatory_address(self.addr_from))

        if not vote_stats.apply_vote_stats(self, weight, state_container):
            logger.info("[MultiSigVote] Failed to apply vote_stats")
            return False

        return self._apply_state_changes_for_PK(state_container)

    def revert(self,
               state: State,
               state_container: StateContainer) -> bool:
        vote_stats = state_container.votes_stats[self.shared_key]
        multi_sig_address = vote_stats.multi_sig_address

        weight, found = state_container.addresses_state[multi_sig_address].get_weight_by_signatory(self.addr_from)
        if not found:
            logger.info("[MultiSigVote] Address is not the signatory for the multi sig address")
            return False

        if not vote_stats.revert_vote_stats(self, weight, state_container):
            logger.info("[MultiSigVote] Failed to revert vote_stats")
            return False

        address_state = state_container.addresses_state[self.addr_from]
        address_state.update_balance(state_container, self.fee)
        state_container.paginated_tx_hash.remove(address_state, self.txhash)

        return self._revert_state_changes_for_PK(state_container)
