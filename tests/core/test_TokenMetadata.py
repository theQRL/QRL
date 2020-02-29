# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from mock import MagicMock
from unittest import TestCase
from pyqrllib.pyqrllib import sha2_256

from tests.misc.helper import get_slave_xmss
from qrl.core.misc import logger
from qrl.core.State import State
from qrl.core.txs.TransferTokenTransaction import TransferTokenTransaction
from qrl.core.TokenMetadata import TokenMetadata

from tests.misc.helper import set_qrl_dir, get_alice_xmss, get_bob_xmss, get_token_transaction

logger.initialize_default()

alice = get_alice_xmss()
slave = get_slave_xmss()


class TestTokenMetadata(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()

    def test_create_token_metadata(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()

        token_transaction = get_token_transaction(alice_xmss, bob_xmss)
        TokenMetadata.create_token_metadata(self.state, token_transaction, None)

        token_metadata = TokenMetadata.get_token_metadata(self.state, token_transaction.txhash)
        self.assertEqual(token_metadata.token_txhash, token_transaction.txhash)
        self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)

    def test_update_token_metadata(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()

        token_transaction = get_token_transaction(alice_xmss, bob_xmss)
        TokenMetadata.create_token_metadata(self.state, token_transaction, None)

        transfer_token_transaction = TransferTokenTransaction.create(token_txhash=token_transaction.txhash,
                                                                     addrs_to=[alice_xmss.address],
                                                                     amounts=[100000000],
                                                                     fee=1,
                                                                     xmss_pk=bob_xmss.pk)

        TokenMetadata.update_token_metadata(self.state, transfer_token_transaction, None)

        token_metadata = TokenMetadata.get_token_metadata(self.state, token_transaction.txhash)
        self.assertEqual(len(token_metadata.transfer_token_tx_hashes), 2)
        self.assertEqual(token_metadata.transfer_token_tx_hashes[0], token_transaction.txhash)
        self.assertEqual(token_metadata.transfer_token_tx_hashes[1], transfer_token_transaction.txhash)

    def test_get_token_metadata(self):
        token_txhash = bytes(sha2_256(b'alpha'))
        token_metadata = TokenMetadata.create(token_txhash,
                                              [bytes(sha2_256(b'delta')),
                                               bytes(sha2_256(b'gamma'))])
        self.state._db.get_raw = MagicMock(return_value=token_metadata.serialize())
        self.assertEqual(TokenMetadata.get_token_metadata(self.state, token_txhash).to_json(),
                         token_metadata.to_json())

    def test_remove_transfer_token_metadata(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()

        token_transaction = get_token_transaction(alice_xmss, bob_xmss)
        TokenMetadata.create_token_metadata(self.state, token_transaction, None)

        transfer_token = TransferTokenTransaction.create(token_txhash=token_transaction.txhash,
                                                         addrs_to=[alice_xmss.address],
                                                         amounts=[100000000],
                                                         fee=1,
                                                         xmss_pk=bob_xmss.pk)
        transfer_token.sign(alice_xmss)

        TokenMetadata.update_token_metadata(self.state, transfer_token, None)
        token_metadata = TokenMetadata.get_token_metadata(self.state, transfer_token.token_txhash)
        self.assertIn(transfer_token.txhash,
                      token_metadata.transfer_token_tx_hashes)

        TokenMetadata.remove_transfer_token_metadata(self.state, transfer_token, None)
        token_metadata = TokenMetadata.get_token_metadata(self.state, transfer_token.token_txhash)
        self.assertNotIn(transfer_token.txhash,
                         token_metadata.transfer_token_tx_hashes)

    def test_remove_token_metadata(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()

        token_tx = get_token_transaction(alice_xmss, bob_xmss)
        TokenMetadata.create_token_metadata(self.state, token_tx, None)

        token_metadata = TokenMetadata.get_token_metadata(self.state, token_tx.txhash)
        self.assertEqual(token_metadata.token_txhash, token_tx.txhash)
        TokenMetadata.remove_token_metadata(self.state, token_tx, None)
        self.assertIsNone(TokenMetadata.get_token_metadata(self.state, token_tx.txhash))
