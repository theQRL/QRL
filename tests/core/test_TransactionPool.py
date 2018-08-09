# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from mock import Mock, patch

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.State import State
from qrl.core.txs.CoinBase import CoinBase
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.TransactionPool import TransactionPool
from tests.misc.helper import replacement_getTime, set_qrl_dir, get_alice_xmss, get_bob_xmss
from tests.misc.MockHelper.mock_function import MockFunction

logger.initialize_default()


def make_tx(txhash=b'hashbrownies', fee=1, autospec=TransferTransaction, PK=b'publickey', **kwargs):
    return Mock(autospec=autospec, txhash=txhash, fee=fee, PK=PK, **kwargs)


def replacement_from_pbdata(protobuf_tx):
    return protobuf_tx


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestTransactionPool(TestCase):
    """
    TransactionPool sits between incoming Transactions from the network and Blocks.
    First, incoming Transactions are pending Transactions and go into TransactionPool.pending_tx_pool.
    The TxnProcessor has to validate them. Once they are validated, the TxnProcessor puts them into
    TransactionPool.transaction_pool, where they wait to be put into the next mined Block.
    """

    def setUp(self):
        self.txpool = TransactionPool(None)

    def test_add_tx_to_pool(self):
        tx = make_tx()
        result = self.txpool.add_tx_to_pool(tx, 1, replacement_getTime())
        self.assertTrue(result)
        self.assertEqual(len(self.txpool.transactions), 1)

    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', autospec=True)
    def test_add_tx_to_pool_while_full(self, m_is_full_func):
        m_is_full_func.return_value = True
        tx = make_tx()
        result = self.txpool.add_tx_to_pool(tx, 1, replacement_getTime())
        self.assertFalse(result)  # refused to add to the pool
        self.assertEqual(len(self.txpool.transactions), 0)  # remains untouched

    @patch('qrl.core.TransactionPool.config', autospec=True)
    def test_is_full_transaction_pool(self, m_config):
        m_config.user.transaction_pool_size = 2

        result = self.txpool.is_full_transaction_pool()
        self.assertFalse(result)

        tx1 = make_tx(fee=1)
        tx2 = make_tx(fee=2)

        self.txpool.add_tx_to_pool(tx1, 1, replacement_getTime())
        self.txpool.add_tx_to_pool(tx2, 1, replacement_getTime())

        result = self.txpool.is_full_transaction_pool()
        self.assertTrue(result)

    def test_get_tx_index_from_pool(self):
        tx1 = make_tx(txhash=b'red')
        tx2 = make_tx(txhash=b'blue')
        tx3 = make_tx(txhash=b'qrlpink')

        self.txpool.add_tx_to_pool(tx1, 1, replacement_getTime())
        self.txpool.add_tx_to_pool(tx2, 1, replacement_getTime())
        self.txpool.add_tx_to_pool(tx3, 1, replacement_getTime())

        idx = self.txpool.get_tx_index_from_pool(b'qrlpink')
        self.assertEqual(idx, 2)

        idx = self.txpool.get_tx_index_from_pool(b'red')
        self.assertEqual(idx, 0)

        idx = self.txpool.get_tx_index_from_pool(b'ultraviolet')
        self.assertEqual(idx, -1)

    def test_remove_tx_from_pool(self):
        tx1 = make_tx(txhash=b'red')
        tx2 = make_tx(txhash=b'blue')
        tx3 = make_tx(txhash=b'qrlpink')

        self.txpool.add_tx_to_pool(tx1, 1, replacement_getTime())

        # If we try to remove a tx that wasn't there, the transaction pool should be untouched
        self.assertEqual(len(self.txpool.transaction_pool), 1)
        self.txpool.remove_tx_from_pool(tx2)
        self.assertEqual(len(self.txpool.transaction_pool), 1)

        # Now let's remove a tx from the heap. The size should decrease.
        self.txpool.add_tx_to_pool(tx2, 1, replacement_getTime())
        self.txpool.add_tx_to_pool(tx3, 1, replacement_getTime())

        self.assertEqual(len(self.txpool.transaction_pool), 3)
        self.txpool.remove_tx_from_pool(tx2)
        self.assertEqual(len(self.txpool.transaction_pool), 2)

    @patch('qrl.core.TransactionPool.TransactionPool.is_full_pending_transaction_pool', autospec=True)
    def test_update_pending_tx_pool(self, m_is_full_pending_transaction_pool):
        tx1 = make_tx()
        ip = '127.0.0.1'
        m_is_full_pending_transaction_pool.return_value = False

        # Due to the straightforward way the function is written, no special setup is needed to get the tx to go in.
        result = self.txpool.update_pending_tx_pool(tx1, ip)
        self.assertTrue(result)

        # If we try to re-add the same tx to the pending_tx_pool, though, it should fail.
        result = self.txpool.update_pending_tx_pool(tx1, ip)
        self.assertFalse(result)

    @patch('qrl.core.TransactionPool.TransactionPool.is_full_pending_transaction_pool', autospec=True)
    def test_update_pending_tx_pool_tx_already_validated(self, m_is_full_pending_transaction_pool):
        """
        If the tx is already in TransactionPool.transaction_pool, do not add it to pending_tx_pool.
        """
        tx1 = make_tx()
        ip = '127.0.0.1'
        m_is_full_pending_transaction_pool.return_value = False

        self.txpool.add_tx_to_pool(tx1, 1, replacement_getTime())

        result = self.txpool.update_pending_tx_pool(tx1, ip)
        self.assertFalse(result)

    @patch('qrl.core.TransactionPool.TransactionPool.is_full_pending_transaction_pool', autospec=True)
    def test_update_pending_tx_pool_is_full_already(self, m_is_full_pending_transaction_pool):
        tx1 = make_tx()
        ip = '127.0.0.1'
        m_is_full_pending_transaction_pool.return_value = True

        result = self.txpool.update_pending_tx_pool(tx1, ip)
        self.assertFalse(result)

    @patch('qrl.core.TransactionPool.logger')
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_pending_transaction_pool', autospec=True)
    def test_update_pending_tx_pool_rejects_coinbase_txs(self, m_is_full_pending_transaction_pool, m_logger):
        tx1 = CoinBase()
        ip = '127.0.0.1'
        m_is_full_pending_transaction_pool.return_value = False

        result = self.txpool.update_pending_tx_pool(tx1, ip)
        self.assertFalse(result)

    @patch('qrl.core.TransactionPool.config', autospec=True)
    def test_is_full_pending_transaction_pool(self, m_config):
        """
        pending_transaction_pool_size is 3, and pending_transaction_pool_reserve is subtracted out of that, so it's 2.
        Trying to add in 3 transactions with ignore_reserve=True will fail, but if ignore_reserve=False, it will go in.
        However, after that, adding even more transactions will always fail.
        """
        m_config.user.pending_transaction_pool_size = 3
        m_config.user.pending_transaction_pool_reserve = 1

        tx4 = make_tx(txhash=b'red')
        tx1 = make_tx(txhash=b'green')
        tx3 = make_tx(txhash=b'blue')
        tx2 = make_tx(txhash=b'pink')
        ip = '127.0.0.1'

        self.txpool.update_pending_tx_pool(tx1, ip)
        self.txpool.update_pending_tx_pool(tx2, ip)
        result = self.txpool.update_pending_tx_pool(tx3, ip, ignore_reserve=True)
        self.assertFalse(result)
        result = self.txpool.update_pending_tx_pool(tx3, ip, ignore_reserve=False)
        self.assertTrue(result)

        result = self.txpool.update_pending_tx_pool(tx4, ip, ignore_reserve=True)
        self.assertFalse(result)
        result = self.txpool.update_pending_tx_pool(tx4, ip, ignore_reserve=False)
        self.assertFalse(result)

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def test_get_pending_transaction(self):
        """
        Getting a pending transaction also removes it from the TransactionPool.
        Because it may return a single None, or two variables, a funny hack is used in TxnProcessor where the return
        from this function is stored in one variable then unpacked later if it is not None.
        """
        tx1 = make_tx()
        ip = '127.0.0.1'
        self.txpool.update_pending_tx_pool(tx1, ip)

        self.assertEqual(len(self.txpool.pending_tx_pool_hash), 1)
        tx_timestamp = self.txpool.get_pending_transaction()
        self.assertEqual(tx_timestamp[0], tx1)
        self.assertEqual(len(self.txpool.pending_tx_pool_hash), 0)

        tx_timestamp = self.txpool.get_pending_transaction()
        self.assertIsNone(tx_timestamp)

    @patch('qrl.core.TransactionPool.logger')
    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', return_value=make_tx())
    @patch('qrl.core.TransactionPool.TransactionPool.add_tx_to_pool', return_value=True)
    def test_add_tx_from_block_to_pool(self, m_add_tx_to_pool, m_from_pbdata, m_logger):
        m_block = Mock(autospec=Block, block_number=5, headerhash=b'test block header')
        m_block.transactions = [CoinBase(), make_tx(), make_tx()]

        self.txpool.add_tx_from_block_to_pool(m_block, 5)

        self.assertEqual(m_add_tx_to_pool.call_count, 2)  # 2 because the function ignores the Coinbase tx

        # If there is a problem adding to the tx_pool, the logger should be invoked.
        m_add_tx_to_pool.return_value = False
        self.txpool.add_tx_from_block_to_pool(m_block, 5)
        m_logger.warning.assert_called()

    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', new=replacement_from_pbdata)
    def test_remove_tx_in_block_from_pool(self):
        m_block = Mock(autospec=Block)
        tx1 = make_tx(name='Mock TX 1', ots_key=1, PK=b'pk')
        tx2 = make_tx(name='Mock TX 2', ots_key=2, PK=b'pk')
        m_block.transactions = [CoinBase(), tx1, tx2]

        # To remove the tx from the pool we have to add it first!
        self.txpool.add_tx_to_pool(tx1, 5)
        self.txpool.add_tx_to_pool(tx2, 5)
        self.assertEqual(len(self.txpool.transaction_pool), 2)

        self.txpool.remove_tx_in_block_from_pool(m_block)
        self.assertEqual(len(self.txpool.transaction_pool), 0)

    @patch('qrl.core.TransactionInfo.config', autospec=True)
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', return_value=False)
    def test_check_stale_txn(self, m_is_full_transaction_pool, m_config):
        """
        Stale Transactions are Transactions that were supposed to go into block 5, but for some reason didn't make it.
        They languish in TransactionPool until check_stale_txn() checks the Pool and updates the tx_info to make them
        go into a higher block.
        For each stale transaction, P2PFactory.broadcast_tx() will be called.
        """

        # Redefine at what point should txs be considered stale
        m_config.user.stale_transaction_threshold = 2
        bob_xmss = get_bob_xmss(4)
        alice_xmss = get_alice_xmss(4)

        tx1 = TransferTransaction.create(addrs_to=[bob_xmss.address], amounts=[1000000], fee=1, xmss_pk=alice_xmss.pk)
        tx1.sign(alice_xmss)
        tx2 = TransferTransaction.create(addrs_to=[bob_xmss.address], amounts=[10000], fee=1, xmss_pk=alice_xmss.pk)
        tx2.sign(alice_xmss)
        m_broadcast_tx = Mock(name='Mock Broadcast TX function (in P2PFactory)')
        self.txpool.add_tx_to_pool(tx1, 5)
        self.txpool.add_tx_to_pool(tx2, 5)
        self.txpool.set_broadcast_tx(m_broadcast_tx)

        with set_qrl_dir('no_data'):
            state = State()
            self.txpool.check_stale_txn(state, 8)

            self.assertEqual(m_broadcast_tx.call_count, 0)

            m = MockFunction()
            bob_address_state = AddressState.get_default(bob_xmss.address)
            bob_address_state.pbdata.balance = 1000000000000
            m.put(bob_xmss.address, bob_address_state)
            state.get_address_state = m.get
            tx3 = TransferTransaction.create(addrs_to=[alice_xmss.address], amounts=[10000], fee=1,
                                             xmss_pk=bob_xmss.pk)
            tx3.sign(bob_xmss)
            self.txpool.add_tx_to_pool(tx3, 5)
            self.txpool.check_stale_txn(state, 8)

            self.assertEqual(m_broadcast_tx.call_count, 1)


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestTransactionPoolRemoveTxInBlockFromPool(TestCase):
    """
    Up until 4096 (max_ots_tracking_index), the state of each OTS index USED/UNUSED is stored in a bitfield.
    Default height of wallet is 12, so 2^12 = 4096 obviously
    Above that however, the network only keeps track of the last used OTS index as a number. So the next
    tx.ots_index must be 4096 < ots_index < network_ots_index_counter (AddressState.ots_counter).

    Suppose you have a Block with two Transactions from the same public address in it, with ots_index=4098 and 4099.
    If TransactionPool has 4097, it should be invalidated because 4098 is already used and we are on an counter
    method of keeping track of OTS indexes.
    Of course, 4098 and 4099 also have to be deleted.
    """

    @patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
    def setUp(self):

        self.txpool = TransactionPool(None)

        self.tx_3907 = make_tx(name='Mock TX 3907', txhash=b'h3907', ots_key=3907)

        self.tx_4095 = make_tx(name='Mock TX 4095', txhash=b'h4095', ots_key=4095)
        self.tx_4096 = make_tx(name='Mock TX 4096', txhash=b'h4096', ots_key=4096)
        self.tx_4097 = make_tx(name='Mock TX 4097', txhash=b'h4097', ots_key=4097)
        self.tx_4098 = make_tx(name='Mock TX 4098', txhash=b'h4098', ots_key=4098)
        self.tx_4099 = make_tx(name='Mock TX 4099', txhash=b'h4099', ots_key=4099)
        self.tx_4100 = make_tx(name='Mock TX 4100', txhash=b'h4100', ots_key=4100)
        self.tx_4200 = make_tx(name='Mock TX 4200', txhash=b'h4200', ots_key=4200)

        # To remove the tx from the pool we have to add it first!
        self.txpool.add_tx_to_pool(self.tx_4095, 5)
        self.txpool.add_tx_to_pool(self.tx_4096, 5)
        self.txpool.add_tx_to_pool(self.tx_4097, 5)
        self.txpool.add_tx_to_pool(self.tx_4098, 5)
        self.txpool.add_tx_to_pool(self.tx_4099, 5)
        self.txpool.add_tx_to_pool(self.tx_4100, 5)
        self.txpool.add_tx_to_pool(self.tx_4200, 5)

    @patch('qrl.core.TransactionPool.config', autospec=True)
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', return_value=False)
    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', new=replacement_from_pbdata)
    def test_block_4098_4099(self, m_is_full_transaction_pool, m_config):
        """
        TxPool = [4095-4100, 4200]
        Block = [4098, 4099]
        TxPool Afterwards = [4095, 4100, 4200]
        """
        # Ensure that a "large OTS index" is 4096
        m_config.dev.max_ots_tracking_index = 4096

        m_block = Mock(autospec=Block)
        m_block.transactions = [CoinBase(), self.tx_4098, self.tx_4099]

        self.txpool.remove_tx_in_block_from_pool(m_block)
        txs_in_txpool = [t[1].transaction for t in self.txpool.transaction_pool]

        self.assertEqual(len(self.txpool.transaction_pool), 3)
        self.assertNotIn(self.tx_4097, txs_in_txpool)
        self.assertNotIn(self.tx_4098, txs_in_txpool)
        self.assertNotIn(self.tx_4099, txs_in_txpool)

        self.assertIn(self.tx_4095, txs_in_txpool)
        self.assertIn(self.tx_4100, txs_in_txpool)
        self.assertIn(self.tx_4200, txs_in_txpool)

    @patch('qrl.core.TransactionPool.config', autospec=True)
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', return_value=False)
    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', new=replacement_from_pbdata)
    def test_txpool_3907_block_4098_4099(self, m_is_full_transaction_pool, m_config):
        """
        TxPool = [3907, 4095-4100, 4200]
        Block = [4098, 4099]
        TxPool Afterwards = [3907, 4095, 4100, 4200]
        """
        # Ensure that a "large OTS index" is 4096
        m_config.dev.max_ots_tracking_index = 4096

        m_block = Mock(autospec=Block)
        m_block.transactions = [CoinBase(), self.tx_4098, self.tx_4099]

        self.txpool.add_tx_to_pool(self.tx_3907, 5)

        self.txpool.remove_tx_in_block_from_pool(m_block)
        txs_in_txpool = [t[1].transaction for t in self.txpool.transaction_pool]

        # 3907 should also be in the Pool since it is exempt from the counter
        self.assertEqual(len(self.txpool.transaction_pool), 4)
        self.assertNotIn(self.tx_4097, txs_in_txpool)
        self.assertNotIn(self.tx_4098, txs_in_txpool)
        self.assertNotIn(self.tx_4099, txs_in_txpool)

        self.assertIn(self.tx_3907, txs_in_txpool)
        self.assertIn(self.tx_4095, txs_in_txpool)
        self.assertIn(self.tx_4100, txs_in_txpool)
        self.assertIn(self.tx_4200, txs_in_txpool)

    @patch('qrl.core.TransactionPool.config', autospec=True)
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', return_value=False)
    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', new=replacement_from_pbdata)
    def test_block_4200(self, m_is_full_transaction_pool, m_config):
        """
        TxPool = [3907, 4095-4100, 4200]
        Block = [4200]
        TxPool Afterwards = [3907, 4095]
        """
        # Ensure that a "large OTS index" is 4096
        m_config.dev.max_ots_tracking_index = 4096

        m_block = Mock(autospec=Block)
        m_block.transactions = [CoinBase(), self.tx_4200]

        self.txpool.add_tx_to_pool(self.tx_3907, 5)

        self.txpool.remove_tx_in_block_from_pool(m_block)
        txs_in_txpool = [t[1].transaction for t in self.txpool.transaction_pool]

        self.assertEqual(len(self.txpool.transaction_pool), 2)
        self.assertIn(self.tx_3907, txs_in_txpool)
        self.assertIn(self.tx_4095, txs_in_txpool)

    @patch('qrl.core.TransactionPool.config', autospec=True)
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', return_value=False)
    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', new=replacement_from_pbdata)
    def test_txpool_4095_4096_4097_otherppl_block_4098_4099(self, m_is_full_transaction_pool, m_config):
        """
        TxPool = [4096-4100, 4200, 4095-4097_otherppl]
        Block = [4200]
        TxPool Afterwards = [4095, 4095-4097_otherppl]
        """
        # Ensure that a "large OTS index" is 4096
        m_config.dev.max_ots_tracking_index = 4096

        m_block = Mock(autospec=Block)
        m_block.transactions = [CoinBase(), self.tx_4200]

        tx_other_4095 = make_tx(name='Mock TX 4095', txhash=b'h4095_other', ots_key=4095, PK='otherppl')
        tx_other_4096 = make_tx(name='Mock TX 4096', txhash=b'h4096_other', ots_key=4096, PK='otherppl')
        tx_other_4097 = make_tx(name='Mock TX 4097', txhash=b'h4097_other', ots_key=4097, PK='otherppl')

        self.txpool.add_tx_to_pool(tx_other_4095, 5)
        self.txpool.add_tx_to_pool(tx_other_4096, 5)
        self.txpool.add_tx_to_pool(tx_other_4097, 5)

        self.txpool.remove_tx_in_block_from_pool(m_block)
        txs_in_txpool = [t[1].transaction for t in self.txpool.transaction_pool]

        self.assertEqual(len(self.txpool.transaction_pool), 4)
        self.assertIn(self.tx_4095, txs_in_txpool)
        self.assertIn(tx_other_4095, txs_in_txpool)
        self.assertIn(tx_other_4096, txs_in_txpool)
        self.assertIn(tx_other_4097, txs_in_txpool)

    @patch('qrl.core.TransactionPool.config', autospec=True)
    @patch('qrl.core.TransactionPool.TransactionPool.is_full_transaction_pool', return_value=False)
    @patch('qrl.core.txs.Transaction.Transaction.from_pbdata', new=replacement_from_pbdata)
    def test_block_1000(self, m_is_full_transaction_pool, m_config):
        """
        TxPool = [4095-4100, 4200]
        Block = [1000]
        TxPool Afterwards = [4095-4100, 4200]
        """
        # Ensure that a "large OTS index" is 4096
        m_config.dev.max_ots_tracking_index = 4096

        tx_1000 = make_tx(name='Mock TX 1000', txhash=b'h1000', ots_key=1000)
        m_block = Mock(autospec=Block)
        m_block.transactions = [CoinBase(), tx_1000]
        self.assertEqual(7, len(self.txpool.transaction_pool))

        self.txpool.remove_tx_in_block_from_pool(m_block)

        txs_in_txpool = [t[1].transaction for t in self.txpool.transaction_pool]
        self.assertEqual(7, len(txs_in_txpool))
