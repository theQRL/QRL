# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase
from mock import patch, Mock, PropertyMock
from pyqrllib.pyqrllib import sha2_256
from collections import OrderedDict

from tests.misc.helper import get_alice_xmss, get_bob_xmss, get_slave_xmss
from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.Block import Block
from qrl.core.BlockHeader import BlockHeader
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.txs.CoinBase import CoinBase
from qrl.crypto.misc import merkle_tx_hash

from tests.misc.helper import replacement_getTime

alice = get_alice_xmss()
bob = get_bob_xmss()
slave = get_slave_xmss()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestBlockReal(TestCase):
    # These tests rely on a real BlockHeader
    def setUp(self):
        self.block = Block.create(block_number=5,
                                  prev_headerhash=bytes(sha2_256(b'test')),
                                  prev_timestamp=10,
                                  transactions=[],
                                  miner_address=alice.address)

    def test_update_mining_address(self):
        self.block.update_mining_address(mining_address=bob.address)
        coinbase_tx = Transaction.from_pbdata(self.block.transactions[0])
        self.assertTrue(isinstance(coinbase_tx, CoinBase))
        self.assertEqual(coinbase_tx.addr_to, bob.address)
        hashedtransactions = []
        for tx in self.block.transactions:
            hashedtransactions.append(tx.transaction_hash)
        self.assertEqual(self.block.blockheader.tx_merkle_root, merkle_tx_hash(hashedtransactions))

    def test_mining_blob(self):
        self.block.set_nonces(mining_nonce=5, extra_nonce=4)

        mining_blob = self.block.mining_blob
        self.assertEqual(len(mining_blob), config.dev.mining_blob_size)
        mining_nonce_bytes = mining_blob[config.dev.mining_nonce_offset:config.dev.mining_nonce_offset + 4]
        extra_nonce_bytes = mining_blob[config.dev.extra_nonce_offset:config.dev.extra_nonce_offset + 8]

        mining_nonce = int.from_bytes(mining_nonce_bytes, byteorder='big', signed=False)
        extra_nonce = int.from_bytes(extra_nonce_bytes, byteorder='big', signed=False)

        self.assertEqual(mining_nonce, 5)
        self.assertEqual(extra_nonce, 4)

    def test_serialize_deserialize(self):
        output = self.block.serialize()
        block_2 = Block.deserialize(output)
        self.assertEqual(block_2, self.block)


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestBlock(TestCase):
    def setUp(self):
        self.blockheader = Mock(name='mock BlockHeader', autospec=BlockHeader, block_number=5,
                                headerhash=bytes(sha2_256(b'mock headerhash')),
                                prev_headerhash=bytes(sha2_256(b'test')))

        self.block = Block.create(block_number=5,
                                  prev_headerhash=bytes(sha2_256(b'test')),
                                  prev_timestamp=10,
                                  transactions=[],
                                  miner_address=alice.address)
        self.block.blockheader = self.blockheader

    def test_set_mining_nonce_from_blob(self):
        current_mining_nonce = self.block.mining_nonce
        current_headerhash = self.block.headerhash
        mining_blob = self.block.mining_blob
        self.block.blockheader.set_mining_nonce_from_blob(mining_blob)
        self.assertEqual(self.block.blockheader.mining_nonce, current_mining_nonce)
        self.assertEqual(self.block.headerhash, current_headerhash)
        self.assertEqual(self.block.blockheader.mining_blob, mining_blob)

    def test_epoch(self):
        # Epoch should follow this formula: block_number // blocks_per_epoch
        self.assertEqual(self.block.epoch, int(self.block.block_number // config.dev.blocks_per_epoch))

    def test_verify_blob(self):
        m_blockheader = Mock()
        self.block.blockheader = m_blockheader

        self.block.verify_blob(b'blob')
        m_blockheader.verify_blob.assert_called_once_with(b'blob')

    def test_validate(self):
        # 1. Set up all the mocking so that Block.validate() should pass
        m_chain_manager = Mock(name='Mock ChainManager')
        attrs_all_pass = {
            'get_block_is_duplicate.return_value': False,
            'validate_mining_nonce.return_value': True,
        }
        m_chain_manager.configure_mock(**attrs_all_pass)
        self.block._validate_parent_child_relation = Mock(return_value=True)

        result = self.block.validate(m_chain_manager, OrderedDict())
        self.assertTrue(result)

        # 2. Switch the mock checks one by one to invalid, and make sure that validate() returns False
        # The Block is already in the State (a duplicate)
        m_chain_manager.get_block_is_duplicate.return_value = True
        result = self.block.validate(m_chain_manager, OrderedDict())
        self.assertFalse(result)
        m_chain_manager.get_block_is_duplicate.return_value = False

        # The mining nonce is invalid
        m_chain_manager.validate_mining_nonce.return_value = False
        result = self.block.validate(m_chain_manager, OrderedDict())
        self.assertFalse(result)
        m_chain_manager.validate_mining_nonce.return_value = True

        # No parent block found, and it's not in future_blocks either
        m_chain_manager.get_block.return_value = None
        result = self.block.validate(m_chain_manager, OrderedDict())
        self.assertFalse(result)
        m_chain_manager.get_block.return_value = Mock(name='mock Block')

        # The parent_block is not actually Block's parent
        self.block._validate_parent_child_relation.return_value = False
        result = self.block.validate(m_chain_manager, OrderedDict())
        self.assertFalse(result)
        self.block._validate_parent_child_relation.return_value = True

        # Block.transactions is [] (it should at least have the CoinBase TX in there)
        with patch('qrl.core.Block.Block.transactions', new_callable=PropertyMock) as m_transactions:
            m_transactions.return_value = []
            result = self.block.validate(m_chain_manager, OrderedDict())
            self.assertFalse(result)

        # There was a problem with the CoinBase TX
        with patch('qrl.core.txs.CoinBase.CoinBase.validate_extended') as m_validate_extended:
            m_validate_extended.return_value = False
            result = self.block.validate(m_chain_manager, OrderedDict())
            self.assertFalse(result)
            m_validate_extended.return_value = None

            m_validate_extended.side_effect = Exception
            result = self.block.validate(m_chain_manager, OrderedDict())
            self.assertFalse(result)

        # The BlockHeader doesn't fit with this Block
        self.blockheader.validate.return_value = False
        result = self.block.validate(m_chain_manager, OrderedDict())
        self.assertFalse(result)

    def test_is_future_block(self):
        self.blockheader.timestamp = replacement_getTime() + config.dev.block_max_drift + 1
        result = self.block.is_future_block()
        self.assertTrue(result)

        self.blockheader.timestamp = replacement_getTime()
        result = self.block.is_future_block()
        self.assertFalse(result)

    def test_validate_parent_child_relation(self):
        self.block._validate_parent_child_relation(Mock())
        self.blockheader.validate_parent_child_relation.assert_called_once()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
@patch('qrl.core.txs.CoinBase.CoinBase.apply_state_changes', name='mock CoinBase.apply_state_changes()',
       return_value=True)
@patch('qrl.core.txs.TransferTransaction.TransferTransaction.apply_state_changes',
       name='mock Transfer.apply_state_changes()', return_value=True)
@patch('qrl.core.txs.TransferTransaction.TransferTransaction.validate_extended',
       name='mock Transfer.validate_extended()', return_value=True)
@patch('qrl.core.txs.TransferTransaction.TransferTransaction.validate', name='mock Transfer.validate()',
       return_value=True)
class TestBlockApplyStateChanges(TestCase):
    """
    Block.apply_state_changes() performs validation on the Transactions again before calling their apply_state_changes()

    If I use Mock Transactions, I need to patch out Block's copying of TX.pbdata into Block's own stuff.
    Then patch out the reconstruction of the Transaction.from_pbdata() in apply_state_changes().
    What value does this give me?
    Not having to individually patch out all Transaction methods used in apply_state_changes() (thus making me reliant
    on apply_state_changes() implementation).
    But to make the test fail/pass, I still need to set certain functions to pass/fail, which makes the test somewhat
    reliant on the implementation.

    If I use real Transactions, I end up testing more of the code, and I am surer that it works well.
    I still have to patch out certain functions to set them to pass/fail, so I am still somewhat reliant on the
    implementation.
    """

    def generate_address_states(self, alice_attrs, bob_attrs, slave_attrs):
        address_states = {
            self.alice.address: Mock(name='self.alice AddressState', autospec=AddressState, **alice_attrs),
            self.bob.address: Mock(name='self.bob AddressState', autospec=AddressState, **bob_attrs),
            self.slave.address: Mock(name='self.slave AddressState', autospec=AddressState, **slave_attrs)
        }
        return address_states

    def setUp(self):
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()
        self.slave = get_slave_xmss()

        self.tx1 = TransferTransaction.create(addrs_to=[self.bob.address], amounts=[10], fee=1, xmss_pk=self.alice.pk)
        self.tx2 = TransferTransaction.create(addrs_to=[self.bob.address], amounts=[10], fee=1, xmss_pk=self.slave.pk,
                                              master_addr=self.alice.address)
        # self.tx1 = Mock(autospec=TransferTransaction, addrs_to=[self.bob.address], amounts=[10], fee=1,
        #                 xmss_pk=self.alice.pk)
        # self.tx2 = Mock(autospec=TransferTransaction, addrs_to=[self.bob.address], amounts=[10], fee=1,
        #                 xmss_pk=self.slave.pk, master_addr=self.alice.address)
        self.tx1._data.nonce = 3
        self.tx2._data.nonce = 6
        self.tx1.sign(self.alice)
        self.tx2.sign(self.slave)

        self.block_attrs = {
            "block_number": 5,
            "prev_headerhash": bytes(sha2_256(b'test')),
            "prev_timestamp": 10,
            "transactions": [self.tx1, self.tx2],
            "miner_address": self.alice.address
        }
        self.alice_addrstate_attrs = {'nonce': 2, 'ots_key_reuse.return_value': False}
        self.slave_addrstate_attrs = {'nonce': 5, 'ots_key_reuse.return_value': False}

    def test_all_ok(self, m_TransferTransaction_validate, m_TransferTransaction_validate_extended,
                    m_TransferTransaction_apply_state_changes, m_CoinBase_apply_state_changes):
        address_states = self.generate_address_states(self.alice_addrstate_attrs, {}, self.slave_addrstate_attrs)

        block = Block.create(**self.block_attrs)
        result = block.apply_state_changes(address_states)
        self.assertTrue(result)

    def test_extra_coinbase_tx(self, m_TransferTransaction_validate,
                               m_TransferTransaction_validate_extended,
                               m_TransferTransaction_apply_state_changes,
                               m_CoinBase_apply_state_changes):
        address_states = self.generate_address_states(self.alice_addrstate_attrs, {}, self.slave_addrstate_attrs)

        coinbase_extra = CoinBase.create(500, self.alice.address, 5)
        self.block_attrs["transactions"] = [self.tx1, coinbase_extra, self.tx2]

        block = Block.create(**self.block_attrs)
        result = block.apply_state_changes(address_states)
        self.assertFalse(result)

    def test_bad_nonce_or_ots_reused(self, m_TransferTransaction_validate,
                                     m_TransferTransaction_validate_extended,
                                     m_TransferTransaction_apply_state_changes,
                                     m_CoinBase_apply_state_changes):
        # If a TX was signed by a Slave XMSS, apply_state_changes() should check against the Slave's AddressState.nonce.
        # In this case, tx.nonce = 3 but slave addrstate.nonce = 0
        self.slave_addrstate_attrs['nonce'] = 0
        address_states = self.generate_address_states(self.alice_addrstate_attrs, {}, self.slave_addrstate_attrs)

        block = Block.create(**self.block_attrs)
        result = block.apply_state_changes(address_states)
        self.assertFalse(result)
        self.slave_addrstate_attrs['nonce'] = 5

        # Now we pretend that Alice's OTS key has been reused.
        self.alice_addrstate_attrs['ots_key_reuse.return_value'] = True
        address_states = self.generate_address_states(self.alice_addrstate_attrs, {}, self.slave_addrstate_attrs)
        result = block.apply_state_changes(address_states)
        self.assertFalse(result)
        self.alice_addrstate_attrs['ots_key_reuse.return_value'] = False

        # Now we pretend that Slave's OTS key has been reused.
        self.slave_addrstate_attrs['ots_key_reuse.return_value'] = True
        address_states = self.generate_address_states(self.alice_addrstate_attrs, {}, self.slave_addrstate_attrs)
        result = block.apply_state_changes(address_states)
        self.assertFalse(result)

    def test_tx_validation_fails(self, m_TransferTransaction_validate,
                                 m_TransferTransaction_validate_extended,
                                 m_TransferTransaction_apply_state_changes,
                                 m_CoinBase_apply_state_changes):
        address_states = self.generate_address_states(self.alice_addrstate_attrs, {}, self.slave_addrstate_attrs)
        block = Block.create(**self.block_attrs)

        m_TransferTransaction_validate.return_value = False
        result = block.apply_state_changes(address_states)
        self.assertFalse(result)
        m_TransferTransaction_validate.return_value = True

        m_TransferTransaction_validate_extended.return_value = False
        result = block.apply_state_changes(address_states)
        self.assertFalse(result)
        m_TransferTransaction_validate_extended.return_value = True

        with patch('qrl.core.txs.CoinBase.CoinBase.validate_extended') as m_validate_extended:
            m_validate_extended.return_value = False
            result = block.apply_state_changes(address_states)
            self.assertFalse(result)
