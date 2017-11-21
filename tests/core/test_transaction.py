from unittest import TestCase

import simplejson as json
from mock import Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import logger
from qrl.core.BlockHeader import BlockHeader
from qrl.core.Transaction import Transaction, TransferTransaction, StakeTransaction, CoinBase, Vote
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2

logger.initialize_default(force_console_output=True)

test_json_Simple = """{
  "type": "TRANSFER",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "mGKZMU0UifDCPXC2iWOcnABZWIVjWCy3shQ5thWDpcA=",
  "otsKey": 10,
  "transfer": {
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "100",
    "fee": "1"
  }
}"""

test_json_Stake = """{
  "type": "STAKE",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "BrD8ry4sppKZqKLOMvDAXNFM1h4lqeMk/62KvFqIqn8=",
  "otsKey": 10,
  "stake": {
    "activationBlocknumber": "2",
    "slavePK": "OAeT3r+PcucO9zUe5QBd9sfKIyD/SeDq0MQLGce7HMFJbhmkgsBjUL3AVOTtUqJOyMmUxE+TQdARkKgasJOt6A==",
    "hash": "H5NgPbU7+tXJI5D3NdDLuGF7SrghSukcVmSj0emwCcg="
  }
}"""

test_json_CoinBase = """{
  "type": "COINBASE",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "pioe9/rt+Cqh9WL/CKizzHs8TU9F72x2U78HTfLNoSI=",
  "otsKey": 11,
  "coinbase": {
    "addrTo": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
    "amount": "90"
  }
}"""

test_json_Vote = """{
  "type": "VOTE",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "t3QQ5I6djuFAyLSdYzEVLgkP46zF3NfkzTtOpr+MODk=",
  "otsKey": 11,
  "vote": {
    "blockNumber": "10",
    "hashHeader": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

# TODO: Do the same for Lattice and Duplicate
# TODO: Write test to check after signing (before is there)
# TODO: Fix problems with verifications (positive and negative checks)
# TODO: Check corner cases, parameter boundaries

wrap_message_expected1 = bytearray(b'\xff\x00\x0000000027\x00{"data": 12345, "type": "TESTKEY_1234"}\x00\x00\xff')
wrap_message_expected1b = bytearray(b'\xff\x00\x0000000027\x00{"type": "TESTKEY_1234", "data": 12345}\x00\x00\xff')


class TestSimpleTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSimpleTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):
        # Alice sending coins to Bob
        tx = TransferTransaction.create(addr_from=self.alice.get_address().encode(),
                                        addr_to=self.bob.get_address().encode(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk(),
                                        xmss_ots_index=self.alice.get_index())
        self.assertTrue(tx)

    def test_create_negative_amount(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.get_address().encode(),
                                       addr_to=self.bob.get_address().encode(),
                                       amount=-100,
                                       fee=1,
                                       xmss_pk=self.alice.pk(),
                                       xmss_ots_index=self.alice.get_index())

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.get_address().encode(),
                                       addr_to=self.bob.get_address().encode(),
                                       amount=-100,
                                       fee=-1,
                                       xmss_pk=self.alice.pk(),
                                       xmss_ots_index=self.alice.get_index())

    def test_to_json(self):
        tx = TransferTransaction.create(addr_from=self.alice.get_address().encode(),
                                        addr_to=self.bob.get_address().encode(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk(),
                                        xmss_ots_index=self.alice.get_index())
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_Simple), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_Simple)
        self.assertIsInstance(tx, TransferTransaction)
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TRANSFER)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual('986299314d1489f0c23d70b689639c9c0059588563582cb7b21439b61583a5c0', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual('e2e3d8b08e65b25411af455eb9bb402827fa7b600fa0b36011d62e26899dfa05', bin2hstr(tx.pubhash))

        # Test that specific content was copied over.
        self.assertEqual(b'Qfd5d64455903b8e500a14cafb1c4ea95a1f97562aaaa24d83e5b9dc3861a47386ce9ad15', tx.txto)
        self.assertEqual(100, tx.amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        # If we change amount, fee, txfrom, txto, (maybe include xmss stuff) txhash should change.
        tx = TransferTransaction.create(addr_from=self.alice.get_address().encode(),
                                        addr_to=self.bob.get_address().encode(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk(),
                                        xmss_ots_index=self.alice.get_index())

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass


class TestStakeTransaction(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestStakeTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):
        tx = StakeTransaction.create(activation_blocknumber=2,
                                     xmss=self.alice,
                                     slavePK=self.bob.pk(),
                                     hashchain_terminator=sha256(b'T1'))
        self.assertTrue(tx)

    def test_to_json(self):
        tx = StakeTransaction.create(activation_blocknumber=2,
                                     xmss=self.alice,
                                     slavePK=self.bob.pk(),
                                     hashchain_terminator=sha256(b'T1'))
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_Stake), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_Stake)
        self.assertIsInstance(tx, StakeTransaction)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual('06b0fcaf2e2ca69299a8a2ce32f0c05cd14cd61e25a9e324ffad8abc5a88aa7f', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual('e2e3d8b08e65b25411af455eb9bb402827fa7b600fa0b36011d62e26899dfa05', bin2hstr(tx.pubhash))

        # Test that specific content was copied over.
        self.assertEqual(2, tx.activation_blocknumber)
        self.assertEqual('380793debf8f72e70ef7351ee5005df6c7ca2320ff49e0ead0c40b19c7bb1cc1'
                         '496e19a482c06350bdc054e4ed52a24ec8c994c44f9341d01190a81ab093ade8',
                         bin2hstr(tx.slave_public_key))
        self.assertEqual('1f93603db53bfad5c92390f735d0cbb8617b4ab8214ae91c5664a3d1e9b009c8',
                         bin2hstr(tx.hash))

    def test_validate_tx(self):
        tx = StakeTransaction.create(activation_blocknumber=2,
                                     xmss=self.alice,
                                     slavePK=self.bob.pk(),
                                     hashchain_terminator=sha256(b'T1'))

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We haven't touched the tx: validation should pass
        self.assertTrue(tx.validate_or_raise())

    def test_get_message_hash(self):
        tx = StakeTransaction.create(activation_blocknumber=2,
                                     xmss=self.alice,
                                     slavePK=self.bob.pk(),
                                     hashchain_terminator=sha256(b'T1'))

        # Currently, a Transaction's message is always blank (what is it used for?)
        self.assertEqual('06b0fcaf2e2ca69299a8a2ce32f0c05cd14cd61e25a9e324ffad8abc5a88aa7f',
                         bin2hstr(tuple(tx.get_message_hash())))


class TestCoinBase(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCoinBase, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.alice.set_index(11)

        self.mock_blockheader = Mock(spec=BlockHeader)
        self.mock_blockheader.stake_selector = self.alice.get_address().encode()
        self.mock_blockheader.block_reward = 50
        self.mock_blockheader.fee_reward = 40
        self.mock_blockheader.prev_blockheaderhash = sha256(b'prev_headerhash')
        self.mock_blockheader.block_number = 1
        self.mock_blockheader.headerhash = sha256(b'headerhash')

        self.maxDiff = None

    def test_create(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice)
        self.assertIsInstance(tx, CoinBase)

    def test_to_json(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice)
        txjson = tx.to_json()
        print(txjson)
        self.assertEqual(json.loads(test_json_CoinBase), json.loads(txjson))

    def test_from_txdict(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice)
        self.assertIsInstance(tx, CoinBase)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual('1a1274bedfc53287853c3aea5b8a93d64f2e4dff23ddbf96e52c8033f0107154', bin2hstr(tx.pubhash))

        self.assertEqual('a62a1ef7faedf82aa1f562ff08a8b3cc7b3c4d4f45ef6c7653bf074df2cda122', bin2hstr(tx.txhash))

        # Test that specific content was copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txto)
        self.assertEqual(tx.amount, 90)


class TestVote(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestVote, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.alice.set_index(11)

        self.addr_from = self.alice.get_address().encode()
        self.blocknumber = 10
        self.headerhash = sha256(b'headerhash')

        self.maxDiff = None

    def test_create(self):
        tx = Vote.create(self.addr_from, self.blocknumber, self.headerhash, self.alice)
        self.assertIsInstance(tx, Vote)

    def test_to_json(self):
        tx = Vote.create(self.addr_from, self.blocknumber, self.headerhash, self.alice)
        txjson = tx.to_json()
        print(txjson)
        self.assertEqual(json.loads(test_json_Vote), json.loads(txjson))

    def test_from_txdict(self):
        tx = Vote.create(self.addr_from, self.blocknumber, self.headerhash, self.alice)
        self.assertIsInstance(tx, Vote)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual('1a1274bedfc53287853c3aea5b8a93d64f2e4dff23ddbf96e52c8033f0107154', bin2hstr(tx.pubhash))

        self.assertEqual('b77410e48e9d8ee140c8b49d6331152e090fe3acc5dcd7e4cd3b4ea6bf8c3839', bin2hstr(tx.txhash))
