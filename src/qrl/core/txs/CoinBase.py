from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction


class CoinBase(Transaction):
    """
    CoinBase is the type of transaction to credit the block_reward to
    the stake selector who created the block.
    """

    def __init__(self, protobuf_transaction=None):
        super(CoinBase, self).__init__(protobuf_transaction)

    @property
    def addr_to(self):
        return self._data.coinbase.addr_to

    @property
    def amount(self):
        return self._data.coinbase.amount

    def get_data_bytes(self):
        # nonce only added to the hashable bytes of CoinBase
        return self.master_addr + \
               self.addr_to + \
               self.nonce.to_bytes(8, byteorder='big', signed=False) + \
               self.amount.to_bytes(8, byteorder='big', signed=False)

    @staticmethod
    def create(amount, miner_address, block_number):
        transaction = CoinBase()
        transaction._data.master_addr = config.dev.coinbase_address
        transaction._data.coinbase.addr_to = miner_address
        transaction._data.coinbase.amount = amount
        transaction._data.nonce = block_number + 1
        transaction._data.transaction_hash = transaction.get_data_hash()

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def update_mining_address(self, mining_address: bytes):
        self._data.coinbase.addr_to = mining_address
        self._data.transaction_hash = self.get_data_hash()

    def _coinbase_filter(self):
        pass

    def _get_allowed_access_types(self):
        # FIXME: 0 and 1 are not clear..
        return [0, 1]

    def _get_master_address(self):
        return self.addr_to

    def _validate_custom(self):
        if self.fee != 0:
            logger.warning('Fee for coinbase transaction should be 0')
            return False

        return True

    # noinspection PyBroadException
    def validate_extended(self, block_number: int):
        if self.master_addr != config.dev.coinbase_address:
            logger.warning('Master address doesnt match with coinbase_address')
            logger.warning('%s %s', bin2hstr(self.master_addr), bin2hstr(config.dev.coinbase_address))
            return False

        if not AddressState.address_is_valid(self.addr_to):
            logger.warning('Invalid address addr_from: %s addr_to: %s', bin2hstr(self.master_addr), bin2hstr(self.addr_to))
            return False

        if self.nonce != block_number + 1:
            logger.warning('Nonce %s doesnt match with block_number %s', self.nonce, block_number)
            return False

        return self._validate_custom()

    def apply_state_changes(self, addresses_state):
        if self.addr_to in addresses_state:
            addresses_state[self.addr_to].balance += self.amount
            addresses_state[self.addr_to].transaction_hashes.append(self.txhash)

        addr_from = config.dev.coinbase_address

        if self.master_addr in addresses_state:
            addresses_state[self.master_addr].balance -= self.amount
            addresses_state[self.master_addr].transaction_hashes.append(self.txhash)
            addresses_state[addr_from].increase_nonce()

    def revert_state_changes(self, addresses_state, chain_manager):
        if self.addr_to in addresses_state:
            addresses_state[self.addr_to].balance -= self.amount
            addresses_state[self.addr_to].transaction_hashes.remove(self.txhash)

        addr_from = config.dev.coinbase_address

        if self.master_addr in addresses_state:
            addresses_state[self.master_addr].balance += self.amount
            addresses_state[self.master_addr].transaction_hashes.remove(self.txhash)
            addresses_state[addr_from].decrease_nonce()

    def set_affected_address(self, addresses_set: set):
        addresses_set.add(self.master_addr)
        addresses_set.add(self.addr_to)
