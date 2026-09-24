# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from unittest import TestCase

from qrl.core.Indexer import Indexer
from qrl.core.State import State
from qrl.core.misc import logger
from qrl.generated import qrl_pb2

from tests.misc.helper import set_qrl_dir

logger.initialize_default()


class TestIndexer(TestCase):
    def test_generate_key(self):
        indexer = Indexer(b'token', None)
        self.assertEqual(indexer.generate_key((b'alice', b'token1')), b'token_alice_token1')
        # str components are encoded to bytes
        self.assertEqual(indexer.generate_key((b'alice', 'token1')), b'token_alice_token1')

    def test_generate_key_rejects_non_tuple(self):
        indexer = Indexer(b'token', None)
        with self.assertRaises(Exception):
            indexer.generate_key(b'not-a-tuple')

    def test_generate_key_rejects_unsupported_component(self):
        indexer = Indexer(b'token', None)
        with self.assertRaises(Exception):
            indexer.generate_key((b'alice', 123))

    def test_put_and_load_roundtrip(self):
        with set_qrl_dir('no_data'):
            state = State()
            key = (b'alice', b'token1')

            writer = Indexer(b'token', state._db)
            writer.data[key] = qrl_pb2.TokenBalance(balance=100, decimals=2)
            writer.put()

            reader = Indexer(b'token', state._db)
            self.assertTrue(reader.load(key, qrl_pb2.TokenBalance()))
            self.assertEqual(reader.data[key].balance, 100)
            self.assertEqual(reader.data[key].decimals, 2)

    def test_put_honours_delete_flag(self):
        with set_qrl_dir('no_data'):
            state = State()
            key = (b'alice', b'token1')

            writer = Indexer(b'token', state._db)
            writer.data[key] = qrl_pb2.TokenBalance(balance=100)
            writer.put()

            writer.data[key] = qrl_pb2.TokenBalance(delete=True)
            writer.put()

            reader = Indexer(b'token', state._db)
            self.assertFalse(reader.load(key, qrl_pb2.TokenBalance()))

    def test_remove_deletes_every_key(self):
        with set_qrl_dir('no_data'):
            state = State()
            keys = [(b'alice', b'token1'), (b'bob', b'token2')]

            writer = Indexer(b'token', state._db)
            for key in keys:
                writer.data[key] = qrl_pb2.TokenBalance(balance=7)
            writer.put()

            reader = Indexer(b'token', state._db)
            for key in keys:
                self.assertTrue(reader.load(key, qrl_pb2.TokenBalance()))

            # remove() must iterate the keys of self._data, not its (key, value)
            # pairs; passing a (key, value) tuple to generate_key() raises.
            writer.remove()

            reader = Indexer(b'token', state._db)
            for key in keys:
                self.assertFalse(reader.load(key, qrl_pb2.TokenBalance()))
