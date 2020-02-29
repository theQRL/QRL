# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from pyqrllib.pyqrllib import hstr2bin
from unittest import TestCase

from qrl.core.misc import logger
from qrl.core.AddressState import AddressState
from qrl.core.MultiSigAddressState import MultiSigAddressState
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.txs.multisig.MultiSigCreate import MultiSigCreate
from qrl.core.State import State
from tests.misc.helper import set_qrl_dir, get_bob_xmss, get_alice_xmss, get_random_xmss

logger.initialize_default()


class TestMultiSigAddressState(TestCase):
    def setUp(self):
        with set_qrl_dir('no_data'):
            self.state = State()

    def test_generate_multi_sig_address(self):
        creation_tx_hash = bytes(hstr2bin("5a4c37ef7e5b7cc5a2a58ab730269ed8"
                                          "f4cbf08a005dc3508e31465535e1d6bb"))
        address = MultiSigAddressState.generate_multi_sig_address(creation_tx_hash)
        expected_address = bytes(hstr2bin("1100003674370317e1cac0ca13f896ab5b6472a"
                                          "261ba0d2b2961d3adba1b9060f6e8f7fe2088fb"))
        self.assertEqual(address, expected_address)
        self.assertFalse(OptimizedAddressState.address_is_valid(address))

    def test_address_is_valid(self):
        address = bytes(hstr2bin("110000000000000000000000000000000000000"
                                 "000000000000000000000000000000000000000"))
        self.assertFalse(OptimizedAddressState.address_is_valid(address))

    def test_get_multi_sig_address_state_by_address(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()
        random_xmss = get_random_xmss()

        signatories = [alice_xmss.address, bob_xmss.address]
        weights = [20, 20]
        threshold = 21
        multi_sig_tx = MultiSigCreate.create(signatories,
                                             weights,
                                             threshold,
                                             0,
                                             random_xmss.pk)
        multi_sig_tx.sign(random_xmss)
        multi_sig_address_state = MultiSigAddressState.get_default(multi_sig_tx.txhash,
                                                                   signatories,
                                                                   weights,
                                                                   threshold)
        AddressState.put_address_state(self.state, multi_sig_address_state)
        multi_sig_address_state2 = MultiSigAddressState.get_multi_sig_address_state_by_address(
            self.state._db,
            MultiSigAddressState.generate_multi_sig_address(multi_sig_tx.txhash))

        self.assertEqual(multi_sig_address_state.pbdata, multi_sig_address_state2.pbdata)

    def test_put_multi_sig_addresses_state(self):
        alice_xmss = get_alice_xmss()
        bob_xmss = get_bob_xmss()
        random_xmss = get_random_xmss()

        signatories = [alice_xmss.address, bob_xmss.address]
        weights = [20, 20]
        threshold = 21
        multi_sig_tx = MultiSigCreate.create(signatories,
                                             weights,
                                             threshold,
                                             0,
                                             random_xmss.pk)
        multi_sig_tx.sign(random_xmss)
        multi_sig_address_state = MultiSigAddressState.get_default(multi_sig_tx.txhash,
                                                                   signatories,
                                                                   weights,
                                                                   threshold)

        multi_sig_addresses_state = {multi_sig_address_state.address: multi_sig_address_state}
        AddressState.put_addresses_state(self.state, multi_sig_addresses_state)

        multi_sig_address_state2 = MultiSigAddressState.get_multi_sig_address_state_by_address(
            self.state._db,
            MultiSigAddressState.generate_multi_sig_address(multi_sig_tx.txhash))
        self.assertEqual(multi_sig_address_state.pbdata, multi_sig_address_state2.pbdata)
