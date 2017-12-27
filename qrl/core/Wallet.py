# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple
from typing import List

from pyqrllib.pyqrllib import mnemonic2bin

from qrl.generated import qrl_pb2
from qrl.core import config
from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS

import os

AddressBundle = namedtuple('AddressBundle', 'address xmss')


class Wallet:
    # TODO: Extremely simple persistance. Upgrade to protobuf / encrypt / etc.
    # TODO: Allow for wallets to be removed / modified?
    # TODO: Consider error handling in the new version
    def __init__(self, valid_or_create=True):
        """
        >>> Wallet().address_bundle is not None
        True
        """
        config.create_path(config.user.wallet_dir)
        self.wallet_dat_filename = os.path.join(config.user.wallet_dir, config.dev.wallet_dat_filename)

        self.address_bundle = None
        self._read_wallet()

        if valid_or_create:
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

    def _read_wallet(self):
        self.address_bundle = []

        if not os.path.isfile(self.wallet_dat_filename):
            return

        try:
            with open(self.wallet_dat_filename, "rb") as infile:
                wallet_store = qrl_pb2.WalletStore()
                wallet_store.ParseFromString(bytes(infile.read()))

                self.address_bundle = []
                for a in wallet_store.wallets:
                    tmpxmss = XMSS(config.dev.xmss_tree_height, mnemonic2bin(a.mnemonic.strip()))
                    tmpxmss.set_index(a.xmss_index)
                    if a.address.encode() != tmpxmss.get_address():
                        logger.fatal("Mnemonic and address do not match.")
                        exit(1)
                    self.address_bundle.append(AddressBundle(tmpxmss.get_address(), tmpxmss))

        except Exception as e:
            logger.warning("It was not possible to open the wallet: %s", e)

    def _valid_or_create(self):
        if self.address_bundle is None or len(self.address_bundle) == 0:
            self.address_bundle = [self.get_new_address()]
            self.save_wallet()

    def append(self, new_addr):
        if new_addr:
            self.address_bundle.append(new_addr)
            self.save_wallet()

    def get_num_signatures(self, address_to_check):
        for addr_bundle in self.address_bundle:
            # FIXME: Linear search?
            if addr_bundle.address == address_to_check:
                return addr_bundle.xmss.get_remaining_signatures()

    @staticmethod
    def get_new_address(signature_tree_height=config.dev.xmss_tree_height,
                        seed=None):
        # type: (int, str) -> AddressBundle
        """
        Get a new wallet address
        The address format is a list of two items [address, data structure from random_mss call]
        :param signature_tree_height:
        :param address_type:
        :param seed:
        :return: a wallet address
        """
        xmss = XMSS(tree_height=signature_tree_height, seed=seed)
        return AddressBundle(xmss.get_address(), xmss)
