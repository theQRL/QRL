# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple
from typing import List

from pyqrllib.pyqrllib import mnemonic2bin

from qrl.generated import qrl_pb2
from qrl.core import config, logger
from qrl.crypto.xmss import XMSS

import os

import simplejson as json       # TODO: Left here for backward compatibility. Remove in next hard fork

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
        config.create_path(config.user.wallet_path)
        self.wallet_dat_filename = os.path.join(config.user.wallet_path, config.dev.wallet_dat_filename)
        self.slave_dat_filename = os.path.join(config.user.wallet_path, config.dev.slave_dat_filename)

        self.address_bundle = None
        self._read_wallet()
        self._valid_or_create()

    @property
    def addresses(self) -> List[bytes]:
        return [a.address for a in self.address_bundle]

    def save_wallet(self):
        logger.debug('Syncing wallet file')

        wallet_store = qrl_pb2.WalletStore()
        wallets = []
        for a in self.address_bundle:
            wallets.append(qrl_pb2.Wallet(address=a.address,
                                          mnemonic=a.xmss.get_mnemonic(),
                                          xmss_index=a.xmss.get_index()))
        wallet_store.wallets.extend(wallets)

        with open(self.wallet_dat_filename, "wb") as outfile:
            outfile.write(wallet_store.SerializeToString())

    def save_slave(self, slave):
        with open(self.slave_dat_filename, "wb") as outfile:
            w = qrl_pb2.Wallet(address=slave.get_address(),
                               mnemonic=slave.get_mnemonic(),
                               xmss_index=slave.get_index())
            outfile.write(w.SerializeToString())

    def read_slave(self):
        if not os.path.isfile(self.slave_dat_filename):
            return
        try:
            with open(self.slave_dat_filename, "rb") as infile:
                w = qrl_pb2.Wallet()
                w.ParseFromString(bytes(infile.read()))
                return AddressSerialized(w.address, w.mnemonic, w.xmss_index)

        except Exception as e:
            logger.warning("It was not possible to open the wallet: %s", e)

    def _read_wallet(self):
        self.address_bundle = None

        if not os.path.isfile(self.wallet_dat_filename):
            upgraded = self._upgrade_old_wallet()
            if not upgraded:
                return

        try:
            logger.info('Retrieving wallet file')
            with open(self.wallet_dat_filename, "rb") as infile:
                wallet_store = qrl_pb2.WalletStore()
                wallet_store.ParseFromString(bytes(infile.read()))

                self.address_bundle = []
                for a in wallet_store.wallets:
                    tmpxmss = XMSS(config.dev.xmss_tree_height, mnemonic2bin(a.mnemonic.strip()))
                    tmpxmss.set_index(a.xmss_index)
                    if a.address != tmpxmss.get_address():
                        logger.fatal("Mnemonic and address do not match.")
                        exit(1)
                    self.address_bundle.append(AddressBundle(tmpxmss.get_address().encode(), tmpxmss))

        except Exception as e:
            logger.warning("It was not possible to open the wallet: %s", e)

    def _upgrade_old_wallet(self):
        wallet_old_dat_filename = os.path.join(config.user.wallet_path, config.dev.wallet_old_dat_filename)
        if not os.path.isfile(wallet_old_dat_filename):
            return False

        logger.info("Found old wallet format. Upgrading")
        try:
            logger.info('Retrieving wallet file')
            with open(wallet_old_dat_filename, "r") as infile:
                data = json.load(infile)
                self.address_bundle = []
                for a in data:
                    tmpxmss = XMSS(config.dev.xmss_tree_height, mnemonic2bin(a['mnemonic'].strip()))
                    tmpxmss.set_index(a['index'])
                    self.address_bundle.append(AddressBundle(tmpxmss.get_address().encode(), tmpxmss))
        except Exception as e:
            logger.warning("It was not possible to open the wallet: %s", e)

        logger.info("Saving in the new format")
        self.save_wallet()

    def _valid_or_create(self):
        if self.address_bundle is None or len(self.address_bundle) == 0:
            self.address_bundle = [self.get_new_address()]
            self.save_wallet()

    def append_wallet(self, new_addr):
        if new_addr:
            self.address_bundle.append(new_addr)
            self.save_wallet()

    def list_addresses(self, persistent_state, transaction_pool, dict_format=False):
        # FIXME: This is called from multiple places and requires external info. Refactor?
        # FIXME: This seems UI related
        list_addr = []
        list_addresses = []
        count = 0

        for addr_bundle in self.address_bundle:
            x = 0
            y = 0
            for t in transaction_pool:
                if t.subtype == qrl_pb2.Transaction.TRANSFER:
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

                # FIXME: Magic number? Unify
                FACTOR = 100000000.000000000
                tmp_state_balance = persistent_state.balance(addr_bundle.address)
                tmp_state_nonce = persistent_state.nonce(addr_bundle.address)

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

    @staticmethod
    def get_new_address(signature_tree_height=config.dev.xmss_tree_height,
                        address_type=ADDRESS_TYPE_XMSS,
                        seed=None):
        # type: (int, str, str) -> AddressBundle
        """
        Get a new wallet address
        The address format is a list of two items [address, data structure from random_mss call]
        :param signature_tree_height:
        :param address_type:
        :param seed:
        :return: a wallet address
        """
        if address_type != Wallet.ADDRESS_TYPE_XMSS:
            raise Exception('OTS type not recognised')

        xmss = XMSS(tree_height=signature_tree_height, seed=seed)
        return AddressBundle(xmss.get_address().encode(), xmss)
