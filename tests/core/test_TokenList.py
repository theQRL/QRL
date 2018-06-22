from unittest import TestCase

from qrl.core.misc import logger
from qrl.core.TokenList import TokenList

logger.initialize_default()


class TestTokenList(TestCase):
    tx_hashes = [b'hash1', b'hash2', b'hash3']

    def setUp(self):
        self.tokenlist = TokenList.create(self.tx_hashes)

    def test_token_txhash(self):
        self.assertEqual(self.tokenlist.token_txhash, self.tx_hashes)

    def test_update(self):
        tokenlist = TokenList.create(self.tx_hashes)
        tokenlist.update([b'hash4', b'hash5'])
        self.assertEqual(tokenlist.token_txhash, [b'hash1', b'hash2', b'hash3', b'hash4', b'hash5'])

    def test_json(self):
        json_data = self.tokenlist.to_json()
        tokenlist_new = TokenList.from_json(json_data)
        self.assertEqual(tokenlist_new.pbdata, self.tokenlist.pbdata)
