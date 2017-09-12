# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple

import qrl.core.Transaction_subtypes
from qrl.core import config, logger
from qrl.crypto.mnemonic import mnemonic_to_seed
from qrl.crypto.xmss import XMSS

import os

import simplejson as json

SIGNATURE_TREE_HEIGHT = 4

AddressBundle = namedtuple('AddressBundle', 'address xmss')
AddressSerialized = namedtuple('AddressSerialized', 'address mnemonic index')


class Wallet:
    # TODO: Extremely simple persistance. Upgrade to protobuf / encrypt / etc.
    # TODO: Allow for wallets to be removed / modified?
    # TODO: Consider error handling in the new version
    ADDRESS_TYPE_XMSS = 'XMSS'

    def __init__(self):
        """
        >>> Wallet().address_bundle is not None
        True
        """
        self.wallet_dat_filename = os.path.join(config.user.wallet_path, config.dev.wallet_dat_filename)
        self.mnemonic_filename = os.path.join(config.user.wallet_path, config.dev.mnemonic_filename)
        self._read_wallet()
        self._valid_or_create()

    def _retrieve_seed_from_mnemonic(self):
        # TODO: Remove. This is legacy
        if not os.path.isfile(self.mnemonic_filename):
            return None

        with open(self.mnemonic_filename, 'r') as f:
            seed_mnemonic = f.read()
            seed = mnemonic_to_seed(seed_mnemonic.strip())
        return seed

    def save_wallet(self):
        logger.info('Syncing wallet file')
        with open(self.wallet_dat_filename, "w") as outfile:
            # map
            data = [AddressSerialized(a.address,
                                      a.xmss.get_mnemonic(),
                                      a.xmss.get_index())
                    for a in self.address_bundle]

            json.dump(data, outfile)

    def _read_wallet(self):
        self.address_bundle = None
        if not os.path.isfile(self.wallet_dat_filename):
            return

        logger.info('Syncing wallet file')
        with open(self.wallet_dat_filename, "r") as infile:
            data = json.load(infile)
            self.address_bundle = []
            for a in data:
                tmpxmss = XMSS(SIGNATURE_TREE_HEIGHT, mnemonic_to_seed(a['mnemonic'].strip()))
                tmpxmss.set_index(a['index'])
                self.address_bundle.append([tmpxmss.get_address(), tmpxmss])

    def _valid_or_create(self):
        if self.address_bundle is None or len(self.address_bundle) == 0:
            self.address_bundle = [self.get_new_address(SIGNATURE_TREE_HEIGHT)]
            self.save_wallet()

    def append_wallet(self, new_addr):
        if new_addr:
            self.address_bundle.append(new_addr)
            self.save_wallet()

    def list_addresses(self, state, transaction_pool, dict_format=False):
        # FIXME: This is called from multiple places and requires external info. Refactor?
        # FIXME: This seems UI related
        addr_bundle_list = self.address_bundle

        list_addr = []
        list_addresses = []
        count = 0

        for addr_bundle in addr_bundle_list:
            x = 0
            y = 0
            for t in transaction_pool:
                if t.subtype == qrl.core.Transaction_subtypes.TX_SUBTYPE_TX:
                    if t.txfrom == addr_bundle.address:
                        y += 1
                        x -= t.amount

                    if t.txto == addr_bundle.address:
                        x += t.amount

            dict_addr = {}

            # add state check for
            # TODO: Refactor this. Properties should be exposed and formatting should be done in webwallet
            if isinstance(addr_bundle.xmss, XMSS):
                dict_addr['address'] = addr_bundle.address
                dict_addr['type'] = addr_bundle.xmss.get_type()

                FACTOR = 100000000.000000000
                tmp_state_balance = state.state_balance(addr_bundle.address)
                tmp_state_nonce = state.state_nonce(addr_bundle.address)

                dict_addr['balance'] = "{} ({})".format(tmp_state_balance / FACTOR, (tmp_state_balance + x) / FACTOR)
                dict_addr['nonce'] = "{} ({})".format(tmp_state_nonce, tmp_state_nonce + y)
                dict_addr['signatures_left'] = "{0} ({0}/{1})".format(addr_bundle.xmss.get_remaining_signatures(),
                                                                      addr_bundle.xmss.get_number_signatures())

                list_addr.append([addr_bundle.address,
                                  'type:', addr_bundle.xmss.get_type(),
                                  'balance: ' + dict_addr['balance'],
                                  'nonce:' + dict_addr['nonce'],
                                  'signatures left: ' + dict_addr['signatures_left']])

            dict_addr['position'] = count
            list_addresses.append(dict_addr)
            count += 1

        if dict_format:
            # FIXME: Changing return types is not clean. Improve
            return list_addr, list_addresses

        return list_addr

    def get_num_signatures(self, address_to_check):
        for addr_bundle in self.address_bundle:
            # FIXME: Linear search?
            if addr_bundle.address == address_to_check:
                return addr_bundle.xmss.get_remaining_signatures()

    def get_new_address(self,
                        signature_tree_height=config.dev.xmss_tree_height,
                        addrtype=ADDRESS_TYPE_XMSS,
                        seed=None):
        # type: (int, str, str) -> AddressBundle
        """
        Get a new wallet address
        The address format is a list of two items [address, data structure from random_mss call]
        :param signature_tree_height:
        :param addrtype:
        :param seed:
        :return: a wallet address
        """
        if addrtype != Wallet.ADDRESS_TYPE_XMSS:
            raise Exception('OTS type not recognised')

        xmss = XMSS(tree_height=signature_tree_height, seed=seed)
        return AddressBundle(xmss.get_address(), xmss)
