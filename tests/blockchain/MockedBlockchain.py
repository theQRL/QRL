import contextlib
from math import ceil, log

from mock import mock, MagicMock, Mock
from pyqryptonight.pyqryptonight import StringToUInt256

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.ChainManager import ChainManager
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.core.qrlnode import QRLNode
from tests.misc.helper import get_alice_xmss, get_bob_xmss, set_qrl_dir


class MockedBlockchain(object):
    MAXNUMBLOCKS = 1000

    def __init__(self, qrlnode, time_mock, ntp_mock):
        required_height = ceil(log(self.MAXNUMBLOCKS, 2))
        required_height = int(required_height + required_height % 2)

        self.qrlnode = qrlnode
        self.time_mock = time_mock
        self.ntp_mock = ntp_mock
        self.alice_xmss = get_alice_xmss(xmss_height=required_height)
        self.bob_xmss = get_bob_xmss()

    def create_block(self, prev_hash, mining_address=None):
        if not mining_address:
            mining_address = self.alice_xmss.address
        transactions = []
        block_prev = self.qrlnode.get_block_from_hash(prev_hash)
        block_idx = block_prev.block_number + 1

        if block_idx == 1:
            slave_tx = SlaveTransaction.create(slave_pks=[self.bob_xmss.pk],
                                               access_types=[0],
                                               fee=0,
                                               xmss_pk=self.alice_xmss.pk)
            slave_tx.sign(self.alice_xmss)
            slave_tx._data.nonce = 1
            transactions = [slave_tx]

        time_offset = 60
        if block_idx % 2 == 0:
            time_offset += 2

        self.time_mock.return_value = self.time_mock.return_value + time_offset
        self.ntp_mock.return_value = self.ntp_mock.return_value + time_offset

        block_new = Block.create(block_number=block_idx,
                                 prev_headerhash=block_prev.headerhash,
                                 prev_timestamp=block_prev.timestamp,
                                 transactions=transactions,
                                 miner_address=mining_address)

        while not self.qrlnode._chain_manager.validate_mining_nonce(blockheader=block_new.blockheader):
            block_new.set_nonces(block_new.mining_nonce + 1, 0)

        return block_new

    def validate(self, block):
        if not block.validate(self.qrlnode._chain_manager, {}):
            raise Exception('Block Validation Failed')

        return True

    def add_block(self, block):
        self.validate(block)
        return self.qrlnode._chain_manager.add_block(block)

    def add_new_block(self, mining_address=None):
        block_prev = self.qrlnode.get_block_last()
        block_new = self.create_block(prev_hash=block_prev.headerhash, mining_address=mining_address)
        self.add_block(block_new)

    @staticmethod
    @contextlib.contextmanager
    def create(num_blocks, mining_address=None):
        tmp_gen = GenesisBlock()
        start_time = tmp_gen.timestamp + config.dev.mining_setpoint_blocktime
        with mock.patch('qrl.core.misc.ntp.getTime') as ntp_mock, \
                set_qrl_dir('no_data'), \
                State() as state, \
                mock.patch('time.time') as time_mock:  # noqa
            time_mock.return_value = start_time
            ntp_mock.return_value = start_time

            state.get_measurement = MagicMock(return_value=10000000)

            genesis_difficulty = config.user.genesis_difficulty
            try:
                config.user.genesis_difficulty = 10
                genesis_block = GenesisBlock()
                chain_manager = ChainManager(state)
                chain_manager.load(genesis_block)

                chain_manager._difficulty_tracker = Mock()
                dt = DifficultyTracker()
                tmp_difficulty = StringToUInt256('2')
                tmp_target = dt.get_target(tmp_difficulty)

                chain_manager._difficulty_tracker.get = MagicMock(return_value=(tmp_difficulty, tmp_target))

                qrlnode = QRLNode(mining_address=b'')
                qrlnode.set_chain_manager(chain_manager)

                mock_blockchain = MockedBlockchain(qrlnode, time_mock, ntp_mock)
                for block_idx in range(1, num_blocks + 1):
                    mock_blockchain.add_new_block(mining_address)

                yield mock_blockchain
            finally:
                config.user.genesis_difficulty = genesis_difficulty
