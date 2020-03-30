from pyqrllib.pyqrllib import bin2hstr, QRLHelper

from qrl.generated import qrl_pb2
from qrl.core.misc import logger
from qrl.core.StateContainer import StateContainer
from qrl.core.PaginatedData import PaginatedData
from qrl.core.txs.multisig.MultiSigVote import MultiSigVote
from qrl.core.State import State


class VoteStats:
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.VoteStats()

    @property
    def pbdata(self):
        return self._data

    def is_active(self, current_block_number) -> bool:
        return not self.executed and current_block_number <= self.expiry_block_number

    @property
    def multi_sig_address(self):
        return self._data.multi_sig_address

    @property
    def expiry_block_number(self):
        return self._data.expiry_block_number

    @property
    def shared_key(self):
        return self._data.shared_key

    @property
    def signatories(self):
        return self._data.signatories

    @property
    def tx_hashes(self):
        return self._data.tx_hashes

    @property
    def unvotes(self):
        return self._data.unvotes

    @property
    def total_weight(self):
        return self._data.total_weight

    @property
    def executed(self):
        return self._data.executed

    def update_total_weight(self, value, subtract):
        if subtract:
            self._data.total_weight -= value
        else:
            self._data.total_weight += value

    def get_address_index(self, address: bytes):
        for i in range(len(self.signatories)):
            if address == self.signatories[i]:
                return i

        return -1

    def get_unvote_by_address(self, address) -> [bool, int]:
        i = self.get_address_index(address)
        if i != -1:
            return self.unvotes[i], i

        return False, -1

    def get_vote_tx_hash_by_signatory_address(self, address):
        i = self.get_address_index(address)
        return self.tx_hashes[i]

    def apply_vote_stats(self,
                         tx: MultiSigVote,
                         weight: int,
                         state_container: StateContainer) -> bool:
        if state_container.block_number > self.expiry_block_number:
            return False

        i = self.get_address_index(tx.addr_from)

        if i == -1:
            return False

        if tx.unvote == self.unvotes[i]:
            return False

        self._data.tx_hashes[i] = tx.txhash

        if tx.unvote:
            self._data.total_weight -= weight
        else:
            self._data.total_weight += weight

        self._data.unvotes[i] = tx.unvote

        multi_sig_spend = state_container.multi_sig_spend_txs[self.shared_key]
        threshold = state_container.addresses_state[self.multi_sig_address].threshold

        # TODO: return bool response of apply function
        self.apply(state_container,
                   multi_sig_spend,
                   state_container.addresses_state,
                   state_container.paginated_tx_hash,
                   state_container.block_number,
                   threshold)

        return True

    def revert_vote_stats(self,
                          tx: MultiSigVote,
                          weight: int,
                          state_container: StateContainer) -> bool:
        if state_container.block_number > self.expiry_block_number:
            return False

        i = self.get_address_index(tx.addr_from)

        if i == -1:
            return False

        if tx.unvote != self.unvotes[i]:
            return False

        if self._data.tx_hashes[i] != tx.txhash:
            return False

        multi_sig_spend = state_container.multi_sig_spend_txs[self.shared_key]
        threshold = state_container.addresses_state[self.multi_sig_address].threshold

        self.revert(state_container,
                    multi_sig_spend,
                    state_container.addresses_state,
                    state_container.paginated_tx_hash,
                    state_container.block_number,
                    threshold)

        self._data.tx_hashes[i] = tx.prev_tx_hash

        if tx.unvote:
            self._data.total_weight += weight
        else:
            self._data.total_weight -= weight

        self._data.unvotes[i] = not tx.unvote

        return True

    @staticmethod
    def create(multi_sig_address: bytes,
               shared_key: bytes,
               signatories: bytes,
               expiry_block_number: int):
        vote_stats = VoteStats()

        vote_stats._data.multi_sig_address = multi_sig_address
        vote_stats._data.shared_key = shared_key
        vote_stats._data.expiry_block_number = expiry_block_number

        for signatory in signatories:
            vote_stats._data.signatories.append(signatory)
            vote_stats._data.tx_hashes.append(b'')
            vote_stats._data.unvotes.append(True)

        return vote_stats

    def apply(self,
              state_container,
              multi_sig_spend,
              addresses_state: dict,
              paginated_tx_hash: PaginatedData,
              current_block_number: int,
              threshold: int) -> bool:
        # TODO: return False if executed
        if self.executed:
            return True

        if self.total_weight < threshold:
            return False

        if current_block_number > self.expiry_block_number:
            return False

        if multi_sig_spend.total_amount > addresses_state[self.multi_sig_address].balance:
            logger.info("[VoteStats] Insufficient funds to execute Multi Sig Spend")
            logger.info("Multi Sig Spend Amount: %s, Funds Available: %s",
                        multi_sig_spend.total_amount,
                        addresses_state[self.multi_sig_address].balance)
            logger.info("Multi Sig Spend txn hash: %s", bin2hstr(multi_sig_spend.txhash))
            logger.info("Multi Sig Address: %s", bin2hstr(multi_sig_spend.multi_sig_address))
            return False

        addresses_state[self.multi_sig_address].update_balance(state_container,
                                                               multi_sig_spend.total_amount,
                                                               subtract=True)

        addr_from_pk = bytes(QRLHelper.getAddress(multi_sig_spend.PK))
        for index in range(0, len(multi_sig_spend.addrs_to)):
            addr_to = multi_sig_spend.addrs_to[index]
            address_state = addresses_state[addr_to]
            if addr_to not in (multi_sig_spend.addr_from, addr_from_pk):
                paginated_tx_hash.insert(address_state, multi_sig_spend.txhash)
            address_state.update_balance(state_container, multi_sig_spend.amounts[index])

        self._data.executed = True
        return True

    def revert(self,
               state_container,
               multi_sig_spend,
               addresses_state: dict,
               paginated_tx_hash: PaginatedData,
               current_block_number: int,
               threshold: int) -> bool:
        if not self.executed:
            return True

        if self.total_weight < threshold:
            return False

        if current_block_number > self.expiry_block_number:
            return False
        addresses_state[self.multi_sig_address].update_balance(state_container, multi_sig_spend.total_amount)

        addr_from_pk = bytes(QRLHelper.getAddress(multi_sig_spend.PK))
        for index in range(0, len(multi_sig_spend.addrs_to)):
            addr_to = multi_sig_spend.addrs_to[index]
            address_state = addresses_state[addr_to]
            if addr_to not in (multi_sig_spend.addr_from, addr_from_pk):
                paginated_tx_hash.remove(address_state, multi_sig_spend.txhash)
            address_state.update_balance(state_container, multi_sig_spend.amounts[index], subtract=True)

        self._data.executed = False
        return True

    def serialize(self):
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrl_pb2.VoteStats()
        pbdata.ParseFromString(bytes(data))
        return VoteStats(pbdata)

    def put_state(self, state: State, batch):
        try:
            state._db.put_raw(b'shared_key_' + self.shared_key, self.serialize(), batch)
        except Exception as e:
            raise Exception("[put_state] Exception in VoteStats %s", e)

    @staticmethod
    def delete_state(state: State, shared_key: bytes, batch):
        try:
            state._db.delete(b'shared_key_' + shared_key, batch)
        except Exception as e:
            raise Exception("[delete_state] Exception in VoteStats %s", e)

    @staticmethod
    def get_state(state: State, shared_key):
        try:
            data = state._db.get_raw(b'shared_key_' + shared_key)
            return VoteStats.deserialize(data)
        except KeyError:
            logger.debug('[get_state] VoteStats %s not found', bin2hstr(shared_key).encode())
        except Exception as e:
            logger.error('[get_state] %s', e)

        return None

    # @staticmethod
    # def apply_and_put(state: State,
    #                   state_container: StateContainer):
    #     for key in state_container.votes_stats:
    #         vote_stats = state_container.votes_stats[key]
    #         multi_sig_spend = state_container.multi_sig_spend_txs[vote_stats.shared_key]
    #         threshold = state_container.addresses_state[vote_stats.multi_sig_address].threshold
    #
    #         vote_stats.apply(state_container,
    #                          multi_sig_spend,
    #                          state_container.addresses_state,
    #                          state_container.paginated_tx_hash,
    #                          state_container.block_number,
    #                          threshold)
    #         vote_stats.put_state(state, state_container.batch)
    #
    #     return True
    #
    # @staticmethod
    # def revert_and_put(state: State,
    #                    state_container: StateContainer):
    #     for key in state_container.votes_stats:
    #         vote_stats = state_container.votes_stats[key]
    #         multi_sig_spend = state_container.multi_sig_spend_txs[vote_stats.shared_key]
    #         threshold = state_container.addresses_state[vote_stats.multi_sig_address].threshold
    #
    #         vote_stats.revert(state_container,
    #                           multi_sig_spend,
    #                           state_container.addresses_state,
    #                           state_container.paginated_tx_hash,
    #                           state_container.block_number,
    #                           threshold)
    #         vote_stats.put_state(state, state_container.batch)
    #
    #     return True

    @staticmethod
    def put_all(state: State,
                state_container: StateContainer):
        for key in state_container.votes_stats:
            vote_stats = state_container.votes_stats[key]
            vote_stats.put_state(state, state_container.batch)

        return True

    @staticmethod
    def revert_all(state: State,
                   state_container: StateContainer):
        for key in state_container.votes_stats:
            vote_stats = state_container.votes_stats[key]
            vote_stats.put_state(state, state_container.batch)

        return True
