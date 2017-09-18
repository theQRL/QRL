# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core.Transaction_subtypes import *

test_txdict_Simple = {
    'subtype': TX_SUBTYPE_TX,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    # >> Signature components
    'i': '1',
    'signature': '1234',
    'merkle_path': '1234',
    'i_bms': '1234',
    'pub': '1234',
    'PK': '1234',
    ############## Specific content
    'txto': '1234',
    'amount': '1234',
    'fee': '1234',
}

test_txdict_Stake = {
    'subtype': TX_SUBTYPE_STAKE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    'i': '1',
    'slave_public_key' : ['1234', '1234'],
    'signature': '1234',
    'merkle_path': '1234',
    'i_bms': '1234',
    'pub': '1234',
    'PK': '1234',
    ############## Specific content
    'epoch': 1,
    'balance': 1,
    'hash': '1234',
    'first_hash': '1234',
}

test_txdict_CoinBase = {
    'subtype': TX_SUBTYPE_COINBASE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    'i': '1',
    'signature': '1234',
    'merkle_path': '1234',
    'i_bms': '1234',
    'pub': '1234',
    'PK': '1234',
    ############## Specific content
    'txto': '1234',
    'amount': '1234',
}

test_txdict_Lattice = {
    'subtype': TX_SUBTYPE_LATTICE,

    'ots_key': 1,
    'nonce': 1,
    'txfrom': '1234',
    'pubhash': '1234',
    'txhash': '1234',
    'i': '1',
    'signature': '1234',
    'merkle_path': '1234',
    'i_bms': '1234',
    'pub': '1234',
    'PK': '1234',
    ############## Specific content
}

wrap_message_expected1 = b'\xff\x00\x00\x00\x00\x00\x1f\x00{"data": 12345, "type": "test"}\x00\x00\xff'
