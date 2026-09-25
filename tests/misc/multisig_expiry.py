# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from contextlib import ExitStack
from unittest import TestCase

from mock import Mock, patch

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.Miner import Miner
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.State import State
from qrl.core.txs.multisig.MultiSigSpend import MultiSigSpend
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_hard_fork_block_number, set_qrl_dir


class MultiSigExpiryTestCase(TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(set_qrl_dir('no_data'))
        stack.enter_context(set_hard_fork_block_number(new_value=1))
        stack.enter_context(patch.object(config.user, 'stale_transaction_threshold', 2))
        stack.enter_context(patch('qrl.core.misc.ntp.getTime', return_value=1526830585))
        self.state = stack.enter_context(State())
        self.alice = get_alice_xmss(4)
        self.bob = get_bob_xmss(4)
        self.tip = 10

        sender = OptimizedAddressState.get_default(self.alice.address)
        sender.pbdata.balance = 1000
        multisig = MultiSigAddressState.create(creation_tx_hash=b'\x01' * 32,
                                               balance=1000,
                                               signatories=[self.alice.address],
                                               weights=[1],
                                               threshold=1,
                                               transaction_hash_count=0)
        self.multisig_address = multisig.address
        AddressState.put_addresses_state(self.state, {sender.address: sender, multisig.address: multisig})

        self.chain_manager = ChainManager(self.state)
        self.chain_manager._last_block = Mock(spec=Block, block_number=self.tip,
                                              headerhash=b'\x02' * 32, timestamp=1526830525)
        self.chain_manager.get_block_by_number = Mock(return_value=Block())
        self.chain_manager.get_block_size_limit = Mock(return_value=1000000)
        self.pool = self.chain_manager.tx_pool
        self.broadcast = Mock()
        self.pool.set_broadcast_tx(self.broadcast)

        # Exercise real block assembly and state transitions without performing PoW.
        stack.enter_context(patch('qrl.core.BlockHeader.BlockHeader._get_qryptonight_hash',
                                  return_value=b'\x03' * 32))
        stack.enter_context(patch('qrl.core.Miner.CNv1Miner'))
        stack.enter_context(patch('qrl.core.Miner.QRandomXMiner'))
        stack.enter_context(patch('qrl.core.Miner.Qryptonight'))
        self.miner = Miner(self.chain_manager, Mock(), self.bob.address, 1)
        self.miner._qn.get_seed_height.return_value = 0

    def make_spend(self, expiry, fee=1):
        tx = MultiSigSpend.create(multi_sig_address=self.multisig_address,
                                  addrs_to=[self.bob.address],
                                  amounts=[100],
                                  expiry_block_number=expiry,
                                  fee=fee,
                                  xmss_pk=self.alice.pk)
        tx.sign(self.alice)
        return tx

    def mine_next_block(self):
        return self.miner.create_block(self.chain_manager.last_block, 0, self.pool, self.bob.address)

    def check_stale(self):
        self.pool.check_stale_txn(self.chain_manager.new_state_container,
                                  self.chain_manager.update_state_container,
                                  self.chain_manager.height)
