from unittest import TestCase

from mock import Mock

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.ChainManager import ChainManager
from qrl.core.txs.SlaveTransaction import SlaveTransaction
from qrl.generated.qrl_pb2 import SlaveMetadata
from tests.misc.helper import get_alice_xmss, get_slave_xmss, set_qrl_dir

logger.initialize_default()


class TestSlaveTransactionStateChanges(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()

        self.alice = get_alice_xmss()
        self.slave = get_slave_xmss()
        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        alice_address_state.pbdata.balance = 100
        self.addresses_state = {
            self.alice.address: alice_address_state,
            self.slave.address: OptimizedAddressState.get_default(self.slave.address)
        }

        self.params = {
            "slave_pks": [self.slave.pk],
            "access_types": [0],
            "fee": 1,
            "xmss_pk": self.alice.pk
        }
        self.unused_chain_manager_mock = Mock(autospec=ChainManager, name='unused ChainManager')

    def test_apply_slave_txn(self):
        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        tx.apply(self.state, state_container)

        self.assertEqual(addresses_state[self.alice.address].balance, 99)

        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([tx.txhash], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertIn((tx.addr_from, tx.slave_pks[0]), state_container.slaves.data)
        data = state_container.slaves.data[(tx.addr_from, tx.slave_pks[0])]
        self.assertIsInstance(data, SlaveMetadata)
        self.assertEqual(tx.access_types[0], data.access_type)
        self.assertEqual(tx.txhash, data.tx_hash)

    def test_revert_slave_txn(self):
        tx = SlaveTransaction.create(**self.params)
        tx.sign(self.alice)
        addresses_state = dict(self.addresses_state)
        addresses_state[self.alice.address].pbdata.balance = 100
        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=Indexer(b'token', None),
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=100,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        tx.apply(self.state, state_container)
        tx.revert(self.state, state_container)

        self.assertEqual(addresses_state[self.alice.address].balance, 100)
        storage_key = state_container.paginated_tx_hash.generate_key(self.alice.address, 1)
        self.assertIn(storage_key, state_container.paginated_tx_hash.key_value)
        self.assertEqual([], state_container.paginated_tx_hash.key_value[storage_key])

        self.assertIn((tx.addr_from, tx.slave_pks[0]), state_container.slaves.data)
        data = state_container.slaves.data[(tx.addr_from, tx.slave_pks[0])]
        self.assertIsInstance(data, SlaveMetadata)
        self.assertEqual(tx.access_types[0], data.access_type)
        self.assertEqual(tx.txhash, data.tx_hash)
