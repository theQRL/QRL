from unittest import TestCase

import simplejson as json
from mock import patch, PropertyMock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.Indexer import Indexer
from qrl.core.misc import logger
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.State import State
from qrl.core.StateContainer import StateContainer
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.generated import qrl_pb2
from tests.core.txs.testdata import test_json_TransferToken, test_signature_TransferToken
from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss, set_qrl_dir

logger.initialize_default()


@patch('qrl.core.txs.Transaction.logger')
class TestTransferTokenTransaction(TestCase):

    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

        self.alice.set_ots_index(10)
        self.maxDiff = None

    def default_params(self):
        params = {
            "token_txhash": b'',
            "addrs_to": [self.bob.address],
            "amounts": [100],
            "fee": 1,
            "xmss_pk": self.alice.pk,
        }
        return params

    def test_create(self, m_logger):
        tx = TransferTokenTransaction.create(token_txhash=b'000000000000000',
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
                                             fee=1,
                                             xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_to_json(self, m_logger):
        tx = TransferTokenTransaction.create(token_txhash=b'000000000000000',
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
                                             fee=1,
                                             xmss_pk=self.alice.pk)
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_TransferToken), json.loads(txjson))

    def test_from_json(self, m_logger):
        tx = Transaction.from_json(test_json_TransferToken)
        tx.sign(self.alice)

        self.assertIsInstance(tx, TransferTokenTransaction)

        # Test that common Transaction components were copied over.
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.addr_from))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.total_amount)
        self.assertEqual('390b159b34cffd29d4271a19679ff227df2ccd471078f177a7b58ca5f5d999f0', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        # z = bin2hstr(tx.signature)
        # print('"', end='')
        # for i in range(len(z)):
        #     print(z[i], end='')
        #     if (i + 1) % 64 == 0:
        #         print('" \\', end='')
        #         print('')
        #         print(' ' * len('test_signature_TransferToken = '), end='')
        #         print('"', end='')

        self.assertEqual(test_signature_TransferToken, bin2hstr(tx.signature))

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self, m_logger):
        tx = TransferTokenTransaction.create(token_txhash=b'000000000000000',
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
                                             fee=1,
                                             xmss_pk=self.alice.pk)

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_validate_tx2(self, m_logger):
        params = self.default_params()
        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)

        self.assertTrue(tx.validate_or_raise())

        tx._data.transaction_hash = b'abc'

        # Should fail, as we have modified with invalid transaction_hash
        with self.assertRaises(ValueError):
            tx.validate_or_raise()

    def test_state_validate_tx_custom(self, m_logger):
        """
        TransferTokenTransaction._validate_custom() checks for:
        1. 0 amounts
        2. fee < 0
        3. multi-send: too many recipients
        4. multi-send: recipient addresses and amounts not the same length
        5. invalid addr_from
        6. invalid addr_to
        """
        slave = get_slave_xmss()
        params = self.default_params()
        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)

        result = tx.validate_or_raise()
        self.assertTrue(result)

        params = self.default_params()
        params["addrs_to"] = [self.bob.address, slave.address]
        params["amounts"] = [1, 0]
        with self.assertRaises(ValueError):
            tx = TransferTokenTransaction.create(**params)

        # Protobuf validation doesn't allow negative fees already
        params = self.default_params()
        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)
        with patch('qrl.core.txs.Transaction.Transaction.fee', new_callable=PropertyMock) as m_fee:
            m_fee.return_value = -1
            with self.assertRaises(ValueError):
                tx.validate_or_raise()

        # TX signing already fails if addrs_to and amounts are unequal length
        params = self.default_params()
        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)
        with patch('qrl.core.txs.TransferTokenTransaction.TransferTokenTransaction.addrs_to',
                   new_callable=PropertyMock) as m_addrs_to:
            m_addrs_to.return_value = [self.bob.address, slave.address]
            with self.assertRaises(ValueError):
                tx.validate_or_raise()

        params = self.default_params()
        params["master_addr"] = b'Bad QRL Address'
        with self.assertRaises(ValueError):
            tx = TransferTokenTransaction.create(**params)

        params = self.default_params()
        params["addrs_to"] = [self.bob.address, b'Bad QRL address']
        params["amounts"] = [100, 200]
        with self.assertRaises(ValueError):
            tx = TransferTokenTransaction.create(**params)

    @patch('qrl.core.txs.Transaction.Transaction.validate_slave', return_value=True)
    def test_validate_extended(self, m_validate_slave, m_logger):
        """
        TransferTokenTransaction._validate_extended checks for:
        1. valid master/slave
        2. negative fee, negative total token amounts transferred
        3. addr_from has enough funds for the fee
        4. if addr_from owns any tokens to begin with
        5. if addr_from has enough tokens
        6. addr_from ots_key reuse
        """
        alice_address_state = OptimizedAddressState.get_default(self.alice.address)
        alice_address_state.pbdata.balance = 100

        params = self.default_params()
        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)

        addresses_state = {
            alice_address_state.address: alice_address_state
        }
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = qrl_pb2.TokenBalance(balance=1000,
                                                                                  decimals=0,
                                                                                  delete=False)

        state_container = StateContainer(addresses_state=addresses_state,
                                         tokens=tokens,
                                         slaves=Indexer(b'slave', None),
                                         lattice_pk=Indexer(b'lattice_pk', None),
                                         multi_sig_spend_txs=dict(),
                                         votes_stats=dict(),
                                         block_number=1,
                                         total_coin_supply=1000,
                                         current_dev_config=config.dev,
                                         write_access=True,
                                         my_db=self.state._db,
                                         batch=None)
        result = tx._validate_extended(state_container)
        self.assertTrue(result)

        # Invalid master XMSS/slave XMSS relationship
        m_validate_slave.return_value = False
        state_container.tokens = Indexer(b'token', None)
        state_container.tokens.data[(self.alice.address, tx.token_txhash)] = qrl_pb2.TokenBalance(balance=1000,
                                                                                                  decimals=0,
                                                                                                  delete=False)
        result = tx.validate_all(state_container)
        self.assertFalse(result)
        m_validate_slave.return_value = True

        # fee = -1
        with patch('qrl.core.txs.TransferTokenTransaction.TransferTokenTransaction.fee',
                   new_callable=PropertyMock) as m_fee:
            m_fee.return_value = -1
            tokens = Indexer(b'token', None)
            tokens.data[(self.alice.address, tx.token_txhash)] = qrl_pb2.TokenBalance(balance=1000,
                                                                                      decimals=0,
                                                                                      delete=False)
            state_container.tokens = tokens
            result = tx._validate_extended(state_container)
            self.assertFalse(result)

        # total_amount = -1
        with patch('qrl.core.txs.TransferTokenTransaction.TransferTokenTransaction.total_amount',
                   new_callable=PropertyMock) as m_total_amount:
            m_total_amount.return_value = -100
            tokens = Indexer(b'token', None)
            tokens.data[(self.alice.address, tx.token_txhash)] = qrl_pb2.TokenBalance(balance=1000,
                                                                                      decimals=0,
                                                                                      delete=False)
            state_container.tokens = tokens
            result = tx._validate_extended(state_container)
            self.assertFalse(result)

        # balance = 0, cannot pay the Transaction fee
        alice_address_state.pbdata.balance = 0
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = qrl_pb2.TokenBalance(balance=1000,
                                                                                  decimals=0,
                                                                                  delete=False)
        state_container.tokens = tokens
        result = tx._validate_extended(state_container)
        self.assertFalse(result)
        alice_address_state.pbdata.balance = 100

        # addr_from doesn't have these tokens
        state_container.tokens = Indexer(b'token', None)
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        # addr_from doesn't have enough tokens
        tokens = Indexer(b'token', None)
        tokens.data[(self.alice.address, tx.token_txhash)] = qrl_pb2.TokenBalance(balance=99,
                                                                                  decimals=0,
                                                                                  delete=False)
        state_container.tokens = tokens
        result = tx._validate_extended(state_container)
        self.assertFalse(result)

        # addr_from_pk has used this OTS key before
        addresses_state = {
            self.alice.address: alice_address_state
        }
        state_container.addresses_state = addresses_state
        # addr_from_pk has used this OTS key before
        state_container.paginated_bitfield.set_ots_key(addresses_state, alice_address_state.address, tx.ots_key)
        result = tx.validate_all(state_container)
        self.assertFalse(result)

        slave = get_slave_xmss()
        params = self.default_params()
        params["addrs_to"] = [self.bob.address, slave.address, self.alice.address]
        params["amounts"] = [2, 3, 5]
        tx = TransferTokenTransaction.create(**params)
        tx.sign(self.alice)
        with patch('qrl.core.config', autospec=True) as m_config:
            m_config.dev = config.dev.create(config.dev.prev_state_key, config.dev.current_state_key,
                                             b'', 10, True, True)
            m_config.dev.pbdata.transaction.multi_output_limit = 1
            state_container.current_dev_config = m_config.dev
            self.assertFalse(tx._validate_extended(state_container=state_container))

    def test_set_affected_address(self, m_logger):
        result = set()
        params = self.default_params()
        tx = TransferTokenTransaction.create(**params)
        tx.set_affected_address(result)
        self.assertEqual(2, len(result))

        params = self.default_params()
        params["addrs_to"] = [self.bob.address, get_slave_xmss().address]
        params["amounts"] = [100, 200]
        tx = TransferTokenTransaction.create(**params)
        tx.set_affected_address(result)
        self.assertEqual(3, len(result))
