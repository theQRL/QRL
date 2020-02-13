# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from mock import MagicMock

from qrl.core import config
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.core.misc import logger, db
from qrl.core.State import State
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.Block import Block

from tests.misc.helper import set_qrl_dir, get_alice_xmss, get_some_address

logger.initialize_default()


class TestTransactionMetadata(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()
        self.m_db = MagicMock(name='mock DB', autospec=db.DB)

    def test_rollback_tx_metadata(self):
        alice_xmss = get_alice_xmss()

        tx1 = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                         amounts=[1, 2],
                                         message_data=None,
                                         fee=0,
                                         xmss_pk=alice_xmss.pk)

        block = Block.create(dev_config=config.dev,
                             block_number=5,
                             prev_headerhash=b'',
                             prev_timestamp=10,
                             transactions=[tx1],
                             miner_address=b'',
                             seed_height=0,
                             seed_hash=None)

        TransactionMetadata.update_tx_metadata(self.state, block=block, batch=None)

        tx_metadata = TransactionMetadata.get_tx_metadata(self.state, tx1.txhash)

        self.assertEqual(tx_metadata[0].to_json(), tx1.to_json())
        TransactionMetadata.rollback_tx_metadata(self.state, block, None)
        self.assertIsNone(TransactionMetadata.get_tx_metadata(self.state, tx1.txhash))

    def test_update_tx_metadata(self):
        alice_xmss = get_alice_xmss()
        tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                        amounts=[1, 2],
                                        message_data=None,
                                        fee=0,
                                        xmss_pk=alice_xmss.pk)
        block_number = 5
        TransactionMetadata.put_tx_metadata(self.state, tx, block_number, 10000, None)

        tx_metadata = TransactionMetadata.get_tx_metadata(self.state, tx.txhash)
        self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
        self.assertEqual(tx_metadata[1], block_number)

    def test_remove_tx_metadata(self):
        self.assertIsNone(TransactionMetadata.get_tx_metadata(self.state, b'test1'))

        alice_xmss = get_alice_xmss()
        tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                        amounts=[1, 2],
                                        message_data=None,
                                        fee=0,
                                        xmss_pk=alice_xmss.pk)
        block_number = 5
        TransactionMetadata.put_tx_metadata(self.state, tx, block_number, 10000, None)

        tx_metadata = TransactionMetadata.get_tx_metadata(self.state, tx.txhash)
        self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
        self.assertEqual(tx_metadata[1], block_number)

        TransactionMetadata.remove_tx_metadata(self.state, tx, None)
        self.assertIsNone(TransactionMetadata.get_tx_metadata(self.state, tx.txhash))

    def test_put_tx_metadata(self):
        self.assertIsNone(TransactionMetadata.get_tx_metadata(self.state, b'test1'))

        alice_xmss = get_alice_xmss()
        tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                        amounts=[1, 2],
                                        message_data=None,
                                        fee=0,
                                        xmss_pk=alice_xmss.pk)
        block_number = 5
        TransactionMetadata.put_tx_metadata(self.state, tx, block_number, 10000, None)

        tx_metadata = TransactionMetadata.get_tx_metadata(self.state, tx.txhash)
        self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
        self.assertEqual(tx_metadata[1], block_number)

    def test_get_tx_metadata(self):
        self.assertIsNone(TransactionMetadata.get_tx_metadata(self.state, b'test1'))

        alice_xmss = get_alice_xmss()
        tx = TransferTransaction.create(addrs_to=[get_some_address(1), get_some_address(2)],
                                        amounts=[1, 2],
                                        message_data=None,
                                        fee=0,
                                        xmss_pk=alice_xmss.pk)
        block_number = 5
        timestamp = 10000
        TransactionMetadata.put_tx_metadata(self.state, tx, block_number, timestamp, None)

        tx_metadata = TransactionMetadata.get_tx_metadata(self.state, tx.txhash)
        self.assertEqual(tx_metadata[0].to_json(), tx.to_json())
        self.assertEqual(tx_metadata[1], block_number)
