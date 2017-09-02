# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.core import logger, config, transaction
from qrl.crypto.misc import sha256
from copy import deepcopy

class StateBuffer:
    def __init__(self):
        self.stake_list = {}
        self.next_stake_list = {}
        self.stxn_state = {}  # key address, value [nonce, balance, pubhash]
        self.next_seed = None  ##
        self.hash_chain = None  ##

    def set_next_seed(self, winning_reveal, prev_seed):
        self.next_seed = sha256(winning_reveal + str(prev_seed))

    @staticmethod
    def tx_to_list(txn_dict):
        tmp_sl = []
        for txfrom in txn_dict:
            st = txn_dict[txfrom]
            if not st[3]:  # rejecting ST having first_hash None
                continue
            tmp_sl.append(st)
        return tmp_sl

    def update(self, state, parent_state_buffer, block):
        # epoch mod, helps you to know if its the new epoch
        epoch_mod = block.blockheader.blocknumber % config.dev.blocks_per_epoch

        self.stake_list = deepcopy(parent_state_buffer.stake_list)
        self.next_stake_list = deepcopy(parent_state_buffer.next_stake_list)
        # TODO filter all next_stake_list with first_reveal None
        # Before adding_block, check if the stake_selector is in stake_list
        self.set_next_seed(block.blockheader.hash, parent_state_buffer.next_seed)
        self.hash_chain = deepcopy(parent_state_buffer.hash_chain)
        self.stxn_state = deepcopy(parent_state_buffer.stxn_state)

        if not epoch_mod:  # State belongs to first block of next epoch
            self.stake_list = self.next_stake_list
            self.next_stake_list = {}

            tmp_sl = self.tx_to_list(self.stake_list)

            self.stake_list = {}
            for st in tmp_sl:
                self.stake_list[st[0]] = st

        if epoch_mod == config.dev.blocks_per_epoch - 1:
            tmp_sl = self.tx_to_list(self.next_stake_list)

            self.next_seed = state.calc_seed(tmp_sl, verbose=False)

        self.update_stake_list(block)
        self.update_next_stake_list(block)
        self.update_stxn_state(block, state)

    def update_stxn_state(self, block, state):
        ignore_addr = set()
        for tx in block.transactions:
            ignore_addr.add(tx.txfrom)  # list of addresses that needs to be included in the buffer

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                ignore_addr.add(tx.txto)
                if tx.txto not in self.stxn_state:
                    self.stxn_state[tx.txto] = state.state_get_address(tx.txto)

            if tx.txfrom not in self.stxn_state:
                self.stxn_state[tx.txfrom] = state.state_get_address(tx.txfrom)

            self.stxn_state[tx.txfrom][2].append(tx.pubhash)

            if tx.subtype == transaction.TX_SUBTYPE_TX:
                self.stxn_state[tx.txfrom][1] -= tx.amount

            if tx.subtype in (transaction.TX_SUBTYPE_TX, transaction.TX_SUBTYPE_COINBASE):
                self.stxn_state[tx.txto][1] += tx.amount

            if tx.txfrom in self.stxn_state:
                if self.stxn_state[tx.txfrom][0] > tx.nonce:
                    continue

            self.stxn_state[tx.txfrom][0] = tx.nonce

        stxn_state_keys = self.stxn_state.keys()
        for addr in stxn_state_keys:
            if addr in ignore_addr:
                continue
            addr_list = state.state_get_address(addr)
            if not addr_list:
                continue

            if self.stxn_state[addr][1] == addr_list[1] and self.stxn_state[addr][2] == addr_list[2]:
                del self.stxn_state[addr]

    def update_next_stake_list(self, block):
        for st in block.transactions:
            if st.subtype != transaction.TX_SUBTYPE_STAKE:
                continue
            balance = st.balance
            if st.txfrom in self.next_stake_list:
                if self.next_stake_list[st.txfrom][3]:
                    continue
                balance = self.next_stake_list[st.txfrom][4]
            self.next_stake_list[st.txfrom] = [st.txfrom, st.hash, 0, st.first_hash, balance]

    def update_stake_list(self, block):
        stake_selector = block.blockheader.stake_selector
        if stake_selector not in self.stake_list:
            logger.error('Error Stake selector not found stake_list of block buffer state')
            raise Exception
        self.stake_list[stake_selector][2] += 1  # Update Nonce