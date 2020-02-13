# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from mock import MagicMock

from qrl.core.LastTransactions import LastTransactions
from qrl.core.misc import logger, db
from qrl.core.State import State
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.Block import Block

from tests.misc.helper import set_qrl_dir, get_alice_xmss, get_some_address

logger.initialize_default()


class TestLastTransactions(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()
        self.m_db = MagicMock(name='mock DB', autospec=db.DB)

    def test_update_last_tx(self):
        alice_xmss = get_alice_xmss()
        # Test Case: When there is no last txns
        self.assertEqual(LastTransactions.get_last_txs(self.state), [])

        block = Block()
        tx1 = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                         amounts=[1, 2],
                                         message_data=None,
                                         fee=0,
                                         xmss_pk=alice_xmss.pk)
        block._data.transactions.extend([tx1.pbdata])
        LastTransactions._update_last_tx(self.state, block, None)
        last_txns = LastTransactions.get_last_txs(self.state)

        # Test Case: When there is only 1 last txns
        self.assertEqual(len(last_txns), 1)
        self.assertEqual(last_txns[0].to_json(), tx1.to_json())

        block = Block()
        tx2 = TransferTransaction.create(addrs_to=[get_some_address(2), get_some_address(3)],
                                         amounts=[1, 2],
                                         message_data=None,
                                         fee=0,
                                         xmss_pk=alice_xmss.pk)

        tx3 = TransferTransaction.create(addrs_to=[get_some_address(4), get_some_address(5)],
                                         amounts=[1, 2],
                                         message_data=None,
                                         fee=0,
                                         xmss_pk=alice_xmss.pk)
        block._data.transactions.extend([tx2.pbdata, tx3.pbdata])
        LastTransactions._update_last_tx(self.state, block, None)
        last_txns = LastTransactions.get_last_txs(self.state)

        # Test Case: When there are 3 last txns
        self.assertEqual(len(last_txns), 3)
        self.assertEqual(last_txns[0].to_json(),
                         tx3.to_json())
        self.assertEqual(last_txns[1].to_json(),
                         tx2.to_json())
        self.assertEqual(last_txns[2].to_json(),
                         tx1.to_json())

    def test_get_last_txs(self):
        self.assertEqual(LastTransactions.get_last_txs(self.state), [])

        alice_xmss = get_alice_xmss()
        block = Block()
        tx1 = TransferTransaction.create(addrs_to=[get_some_address(0), get_some_address(1)],
                                         amounts=[1, 2],
                                         message_data=None,
                                         fee=0,
                                         xmss_pk=alice_xmss.pk)
        block._data.transactions.extend([tx1.pbdata])
        LastTransactions._update_last_tx(self.state, block, None)
        last_txns = LastTransactions.get_last_txs(self.state)

        # Test Case: When there is only 1 last txns
        self.assertEqual(len(last_txns), 1)
        self.assertEqual(last_txns[0].to_json(), tx1.to_json())

    def test_remove_last_tx(self):
        # Test Case: When there is no last txns
        self.assertEqual(LastTransactions.get_last_txs(self.state), [])

        alice_xmss = get_alice_xmss()

        block = Block()
        tx1 = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                         amounts=[1, 2],
                                         message_data=None,
                                         fee=0,
                                         xmss_pk=alice_xmss.pk)
        block._data.transactions.extend([tx1.pbdata])
        LastTransactions._update_last_tx(self.state, block, None)
        last_txns = LastTransactions.get_last_txs(self.state)

        self.assertEqual(last_txns[0].to_json(), tx1.to_json())

        LastTransactions._remove_last_tx(self.state, block, None)
        last_txns = LastTransactions.get_last_txs(self.state)
        self.assertEqual(last_txns, [])
