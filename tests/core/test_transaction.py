from unittest import TestCase

import simplejson as json
from mock import Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core import logger
from qrl.core.BlockHeader import BlockHeader
from qrl.core.Transaction import Transaction, TransferTransaction, StakeTransaction, CoinBase, Vote, TokenTransaction, TransferTokenTransaction
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2

logger.initialize_default(force_console_output=True)

test_json_Simple = """{
  "type": "TRANSFER",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "MzIyNWEwY2NiNWZkYzVjZWM3Yzk3NmIxZDY3MTUwZjU0NjI0MGQwYTMwNzM5MzY2YjM0NGM1MTQxNzAwMmFmYg==",
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
  "transactionHash": "ZWIzMmQzY2M4OWY4MDE4MjhlMTg3YTY5NjQ1NDgwZjFjYTc3NjNjMzJhZjc0ODZmZWYzNDQ0NTcxZDExMjE2Ng==",
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
  "transactionHash": "YzQ4YzM2YTk1YTZjYmE5OWY1ZmMxM2IyZjY2YzVkODc0MDQ1ZGNjYmU0M2ZhODE1ODY3ZGU5ZGJjNGYyYzhlYw==",
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
  "transactionHash": "MjFlOWM1ODc4YTE1Y2VhODRhMzg1MTJiNGNmMGZiNDhjY2Y4ZWEzODViNDdjOGU5ZjQ1MjIzZDk0NmNkODI5Mw==",
  "otsKey": 11,
  "vote": {
    "blockNumber": "10",
    "hashHeader": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

test_json_Token = """{
  "type": "TOKEN",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "M2U4NTkwYjAyZDA0MjUxZTZkMTRlNDQ4NTczOTUyYzk5ZDg2YmY1Njg4NzE3NDk4Y2ZhNGU3NzJkYzI4YzcyMw==",
  "otsKey": 10,
  "token": {
    "symbol": "UVJM",
    "name": "UXVhbnR1bSBSZXNpc3RhbnQgTGVkZ2Vy",
    "owner": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
    "decimals": "4",
    "initialBalances": [
      {
        "address": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
        "amount": "400000000"
      },
      {
        "address": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
        "amount": "200000000"
      }
    ],
    "fee": "1"
  }
}"""

test_json_TransferToken = """{
  "type": "TRANSFERTOKEN",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "ODA0ZGQzYWU1Nzc3N2NiYjdiNmFhOTVmNTQwNzJlNjMxYTU1MjU1NTA3NmE1YjlkNGQ5MDI5MWMzY2RlOGY3Mw==",
  "otsKey": 10,
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "200000",
    "fee": "1"
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
        self.assertEqual(b'3225a0ccb5fdc5cec7c976b1d67150f546240d0a30739366b344c51417002afb', tx.txhash)
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual(b'e2e3d8b08e65b25411af455eb9bb402827fa7b600fa0b36011d62e26899dfa05', tx.pubhash)

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
        self.assertEqual(b'eb32d3cc89f801828e187a69645480f1ca7763c32af7486fef3444571d112166', tx.txhash)
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual(b'e2e3d8b08e65b25411af455eb9bb402827fa7b600fa0b36011d62e26899dfa05', tx.pubhash)

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
        self.assertEqual(b'eb32d3cc89f801828e187a69645480f1ca7763c32af7486fef3444571d112166',
                         tx.get_message_hash())


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
        self.assertEqual(b'1a1274bedfc53287853c3aea5b8a93d64f2e4dff23ddbf96e52c8033f0107154', tx.pubhash)

        self.assertEqual(b'c48c36a95a6cba99f5fc13b2f66c5d874045dccbe43fa815867de9dbc4f2c8ec', tx.txhash)

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
        self.assertEqual(b'1a1274bedfc53287853c3aea5b8a93d64f2e4dff23ddbf96e52c8033f0107154', tx.pubhash)

        self.assertEqual(b'21e9c5878a15cea84a38512b4cf0fb48ccf8ea385b47c8e9f45223d946cd8293', tx.txhash)


class TestTokenTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestTokenTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):
        # Alice creates Token
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.get_address().encode(),
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.get_address().encode(),
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk(),
                                     xmss_ots_index=self.alice.get_index())
        self.assertTrue(tx)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                    symbol=b'QRL',
                                    name=b'Quantum Resistant Ledger',
                                    owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                    decimals=4,
                                    initial_balances=[],
                                    fee=-1,
                                    xmss_pk=self.alice.pk(),
                                    xmss_ots_index=self.alice.get_index())

    def test_to_json(self):
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.get_address().encode(),
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.get_address().encode(),
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk(),
                                     xmss_ots_index=self.alice.get_index())
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_Token), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_Token)
        self.assertIsInstance(tx, TokenTransaction)
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TOKEN)

        # Test that common Transaction components were copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'QRL', tx.symbol)
        self.assertEqual(b'Quantum Resistant Ledger', tx.name)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.owner)
        self.assertEqual(b'3e8590b02d04251e6d14e448573952c99d86bf5688717498cfa4e772dc28c723', tx.txhash)
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual(b'e2e3d8b08e65b25411af455eb9bb402827fa7b600fa0b36011d62e26899dfa05', tx.pubhash)

        total_supply = 0
        for initial_balance in tx.initial_balances:
            total_supply += initial_balance.amount
        self.assertEqual(600000000, total_supply)

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.get_address().encode(),
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.get_address().encode(),
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
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


class TestTransferTokenTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestTransferTokenTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):

        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address().encode(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk(),
                                             xmss_ots_index=self.alice.get_index())
        self.assertTrue(tx)

    def test_to_json(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address().encode(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk(),
                                             xmss_ots_index=self.alice.get_index())
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_TransferToken), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_TransferToken)
        self.assertIsInstance(tx, TransferTokenTransaction)
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TRANSFERTOKEN)

        # Test that common Transaction components were copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.amount)
        self.assertEqual(b'804dd3ae57777cbb7b6aa95f54072e631a552555076a5b9d4d90291c3cde8f73', tx.txhash)
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(b'', tx.signature)
        self.assertEqual(b'e2e3d8b08e65b25411af455eb9bb402827fa7b600fa0b36011d62e26899dfa05', tx.pubhash)

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address().encode(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address().encode(),
                                             amount=200000,
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
