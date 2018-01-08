# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from mock import Mock

from qrl.core.Block import Block
from qrl.core.State import State
from qrl.core.Miner import Miner
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from tests.misc.helper import destroy_state, get_alice_xmss, get_bob_xmss


class TestChainManager(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestChainManager, self).__init__(*args, **kwargs)

    def test_load(self):
        destroy_state()
        state = State()
        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)
        block = state.get_block(GenesisBlock().headerhash)
        self.assertIsNotNone(block)

    def test_add_block(self):
        """
        Testing add_block, with fork logic
        :return:
        """
        destroy_state()
        state = State()
        miner = Miner(Mock())

        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)
        chain_manager.set_miner(miner)


        block = state.get_block(genesis_block.headerhash)
        self.assertIsNotNone(block)

        alice_xmss = get_alice_xmss()

        block_1 = Block.create(mining_nonce=10,
                               block_number=1,
                               prevblock_headerhash=genesis_block.headerhash,
                               transactions=[],
                               signing_xmss=alice_xmss,
                               nonce=1)

        result = chain_manager.add_block(block_1)
        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_1)

        bob_xmss = get_bob_xmss()

        block = Block.create(mining_nonce=15,
                             block_number=1,
                             prevblock_headerhash=genesis_block.headerhash,
                             transactions=[],
                             signing_xmss=bob_xmss,
                             nonce=1)

        result = chain_manager.add_block(block)
        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_1)

        block = state.get_block(block.headerhash)
        self.assertIsNotNone(block)

        block_2 = Block.create(mining_nonce=15,
                               block_number=2,
                               prevblock_headerhash=block.headerhash,
                               transactions=[],
                               signing_xmss=bob_xmss,
                               nonce=2)

        result = chain_manager.add_block(block_2)

        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_2)

    def test_orphan_block(self):
        """
        Testing add_block logic in case of orphan_blocks
        :return:
        """
        destroy_state()
        state = State()
        miner = Mock()
        genesis_block = GenesisBlock()
        chain_manager = ChainManager(state)
        chain_manager.load(genesis_block)
        chain_manager.set_miner(miner)

        block = state.get_block(genesis_block.headerhash)
        self.assertIsNotNone(block)
        alice_xmss = get_alice_xmss()

        block_1 = Block.create(mining_nonce=10,
                               block_number=1,
                               prevblock_headerhash=genesis_block.headerhash,
                               transactions=[],
                               signing_xmss=alice_xmss,
                               nonce=1)
        block_1.set_mining_nonce(10)
        result = chain_manager.add_block(block_1)
        self.assertTrue(result)
        self.assertEqual(chain_manager.last_block, block_1)

        bob_xmss = get_bob_xmss()

        block = Block.create(mining_nonce=15,
                             block_number=1,
                             prevblock_headerhash=genesis_block.headerhash,
                             transactions=[],
                             signing_xmss=bob_xmss,
                             nonce=1)

        block.set_mining_nonce(15)

        block_2 = Block.create(mining_nonce=15,
                               block_number=2,
                               prevblock_headerhash=block.headerhash,
                               transactions=[],
                               signing_xmss=bob_xmss,
                               nonce=2)
        block_2.set_mining_nonce(15)

        result = chain_manager.add_block(block_2)
        self.assertFalse(result)
        result = chain_manager.add_block(block)
        self.assertTrue(result)
        block = state.get_block(block.headerhash)
        self.assertIsNotNone(block)

        self.assertEqual(chain_manager.last_block.block_number, block_2.block_number)
        self.assertEqual(chain_manager.last_block.headerhash, block_2.headerhash)

    def test_diff(self):
        from pyqryptonight.pyqryptonight import Qryptominer
        from time import sleep
        class CustomQMiner(Qryptominer):
            def __init__(self):
                Qryptominer.__init__(self)
                self.nonce = None

            def solutionEvent(self, nonce):
                print('Solution Found %s', nonce)
                self.nonce = nonce

        block_timestamp = 1515443508
        parent_block_timestamp = 1515443508
        parent_difficulty = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4)
        new_diff, new_target = Miner.calc_difficulty(block_timestamp, parent_timestamp=parent_block_timestamp, parent_difficulty=parent_difficulty)
        self.assertEqual(new_diff, (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6))
        self.assertEqual(new_target, (42, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170))
        block_json = '''{
              "transactions": [
                {
                  "publicKey": "KG0suGkuHIbvYEZSsRL4zDo3iZ5fc37jsQHLtl172kGOi6whHeECz1/5DBxrjATEh6L/xBr6NXtcwjQ1YappjA==",
                  "nonce": "2",
                  "signature": "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",
                  "transactionHash": "d1bx0q19bffQyIreiQLBhYJtTuC0fYhc7GUWnZ0IeWI=",
                  "type": "COINBASE",
                  "coinbase": {
                    "addrTo": "UTAyYWQwNzRkYTFjZDc1YmM2YTE4YjE2NTgxM2QyOWNhYWQzMDA0ZDhkZTRkMWYzYjI2ZGQwODhjODE2ZWQ0YTNkNDc2NGYyNw==",
                    "blockNumber": "27",
                    "amount": "461209139"
                  },
                  "addrFrom": "UTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OQ=="
                }
              ],
              "header": {
                "hashHeader": "thnmRQ7hkiIBc+/U2HpJrJypV3/gryR8MOBBC1x7VXY=",
                "PK": "KG0suGkuHIbvYEZSsRL4zDo3iZ5fc37jsQHLtl172kGOi6whHeECz1/5DBxrjATEh6L/xBr6NXtcwjQ1YappjA==",
                "hashHeaderPrev": "JvSNOBlNRIRp2s38w5KzR6HpFGYEuHhw2BW3DzajAbI=",
                "miningNonce": 1,
                "merkleRoot": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                "rewardBlock": "461209139",
                "blockNumber": "27",
                "timestamp": {
                  "seconds": "1515443508"
                }
              }
            }'''
        block = Block.from_json(block_json)
        self.assertEqual(tuple(block.mining_hash), (186, 155, 236, 133, 247, 194, 196, 56, 208, 139, 175, 190, 149, 30, 119, 56, 146, 137, 223, 27, 167, 199, 76, 131, 237, 152, 160, 251, 168, 78, 77, 181))
        input_bytes = [0, 0, 0, 6, 186, 155, 236, 133, 247, 194, 196, 56, 208, 139, 175, 190, 149, 30, 119, 56, 146, 137, 223, 27, 167, 199, 76, 131, 237, 152, 160, 251, 168, 78, 77, 181]
        custom_qminer = CustomQMiner()
        custom_qminer.setInput(input=input_bytes,
                               nonceOffset=0,
                               target=new_target)
        custom_qminer.start(2)
        while not custom_qminer.nonce:
            print(custom_qminer.nonce)
            sleep(1)
        print(custom_qminer.nonce)
        self.assertTrue(custom_qminer.verifyInput(input_bytes, new_target))