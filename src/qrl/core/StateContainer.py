from qrl.core.config import DevConfig
from qrl.core.formulas import block_reward
from qrl.core.Indexer import Indexer
from qrl.core.PaginatedData import PaginatedData
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.misc import db, logger


class StateContainer:
    def __init__(self,
                 addresses_state: dict,
                 tokens: Indexer,
                 slaves: Indexer,
                 lattice_pk: Indexer,
                 multi_sig_spend_txs: dict,
                 votes_stats: dict,
                 block_number: int,
                 total_coin_supply: int,
                 current_dev_config: DevConfig,
                 write_access: bool,
                 my_db: db,
                 batch):
        self.delete_keys = set()
        self.paginated_bitfield = PaginatedBitfield(write_access, my_db)
        self.paginated_tx_hash = PaginatedData(b'p_tx_hash', write_access, my_db)
        self.paginated_tokens_hash = PaginatedData(b'p_tokens', write_access, my_db)
        self.paginated_slaves_hash = PaginatedData(b'p_slaves', write_access, my_db)
        self.paginated_lattice_pk = PaginatedData(b'p_lattice_pk', write_access, my_db)
        self.paginated_multisig_address = PaginatedData(b'p_multisig_address', write_access, my_db)
        self.paginated_multi_sig_spend = PaginatedData(b'p_multi_sig_spend', write_access, my_db)
        self.paginated_inbox_message = PaginatedData(b'p_inbox_message', write_access, my_db)

        self.addresses_state = addresses_state

        self.tokens = tokens
        self.slaves = slaves
        self.lattice_pk = lattice_pk
        self.multi_sig_spend_txs = multi_sig_spend_txs
        self.votes_stats = votes_stats
        self.block_number = block_number  # Block number that is being processed
        self.block_reward = int(block_reward(block_number, current_dev_config))
        self.batch = batch
        self.db = my_db
        self.current_dev_config = current_dev_config

        # Keeps track of last update so that it can be reverted
        self.last_addresses_state = dict()
        self.last_tokens = Indexer(b'token', self.db)
        self.last_slaves = Indexer(b'slave', self.db)
        self.last_lattice_pk = Indexer(b'lattice_pk', self.db)
        self.last_multi_sig_spend_txs = dict()
        self.last_votes_stats = dict()

        self._total_coin_supply = total_coin_supply  # TODO: Coinbase transaction of current block is not included

    @property
    def total_coin_supply(self):
        return self._total_coin_supply

    @staticmethod
    def _copy_key_value(src: dict, dst: dict) -> bool:
        for key in src:
            if key in dst:
                StateContainer._revert_copy_key_value(src, dst, False)
                return False
            dst[key] = src[key]

        return True

    @staticmethod
    def _revert_copy_key_value(src: dict, dst: dict, error_if_key_not_found: bool) -> bool:
        for key in src:
            if key in dst:
                del dst[key]
            elif error_if_key_not_found:
                logger.error("Key %s not found while reverting key from state_container", key)
                return False

        return True

    def update(self,
               addresses_state: dict,
               tokens: Indexer,
               slaves: Indexer,
               lattice_pk: Indexer,
               multi_sig_spend_txs: dict,
               votes_stats: dict) -> bool:

        self.last_addresses_state = addresses_state
        self.last_tokens = tokens
        self.last_slaves = slaves
        self.last_lattice_pk = lattice_pk
        self.last_multi_sig_spend_txs = multi_sig_spend_txs
        self.last_votes_stats = votes_stats

        if not self._copy_key_value(addresses_state, self.addresses_state):
            logger.error("Error updating addresses_state in state_container")
            return False

        if not self._copy_key_value(tokens.data, self.tokens.data):
            logger.error("Error updating tokens in state_container")
            return False

        if not self._copy_key_value(slaves.data, self.slaves.data):
            logger.error("Error updating slaves in state_container")
            return False

        if not self._copy_key_value(lattice_pk.data, self.lattice_pk.data):
            logger.error("Error updating lattice_pk in state_container")
            return False

        if not self._copy_key_value(multi_sig_spend_txs, self.multi_sig_spend_txs):
            logger.error("Error updating multi_sig_spend_txs in state_container")
            return False

        if not self._copy_key_value(votes_stats, self.votes_stats):
            logger.error("Error updating votes_stats in state_container")
            return False

        return True

    def revert_update(self) -> bool:
        if not self._revert_copy_key_value(self.last_addresses_state, self.addresses_state, True):
            logger.error("Error reverting last_addresses_state from state_container")
            return False
        self.last_addresses_state = dict()

        if not self._revert_copy_key_value(self.last_tokens.data, self.tokens.data, True):
            logger.error("Error reverting last_tokens from state_container")
            return False
        self.last_tokens = Indexer(b'token', self.db)

        if not self._revert_copy_key_value(self.last_slaves.data, self.slaves.data, True):
            logger.error("Error reverting last_slaves from state_container")
            return False
        self.last_slaves = Indexer(b'slave', self.db)

        if not self._revert_copy_key_value(self.last_lattice_pk.data, self.lattice_pk.data, True):
            logger.error("Error reverting last_lattice_pk from state_container")
            return False
        self.last_lattice_pk = Indexer(b'lattice_pk', self.db)

        if not self._revert_copy_key_value(self.last_multi_sig_spend_txs, self.multi_sig_spend_txs, True):
            logger.error("Error reverting last_multi_sig_spend_txs from state_container")
            return False
        self.last_multi_sig_spend_txs = dict()

        if not self._revert_copy_key_value(self.last_votes_stats, self.votes_stats, True):
            logger.error("Error reverting last_votes_stats from state_container")
            return False
        self.last_votes_stats = dict()

        return True
