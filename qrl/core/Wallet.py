# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple
from typing import List, Optional, KeysView

import simplejson
from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr, XmssFast

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
        self.wallet_dat_filename = os.path.join(config.user.wallet_dir,
                                                config.dev.wallet_dat_filename)

        self.address_dict = dict()
        self._read_wallet(self.wallet_dat_filename)

        if valid_or_create:
            self._valid_or_create()

    @property
    def addresses(self) -> List[bytes]:
        return list(self.address_dict.keys())

    def get_xmss(self, address)->Optional[XMSS]:
        return self.address_dict.get(address, None)

    def save_wallet(self):
        logger.debug('Syncing wallet file')

        wallet_store = qrl_pb2.WalletStore()
        wallets = []
        for a in self.address_bundle:
            wallets.append(qrl_pb2.Wallet(address=a.address,
                                          mnemonic=a.xmss.mnemonic,
                                          xmss_index=a.xmss.ots_index))
        wallet_store.wallets.extend(wallets)

        with open(self.wallet_dat_filename, "wb") as outfile:
            outfile.write(wallet_store.SerializeToString())

    def _read_wallet(self, filename):
        self.address_bundle = []

        if not os.path.isfile(filename):
            return

        try:
            with open(filename, "rb") as infile:
                wallet_store = simplejson.loads(infile.read())

                self.address_bundle = []
                for a in wallet_store:
                    tmp_xmss = XMSS.from_extended_seed(mnemonic2bin(a['mnemonic'].strip()))
                    tmp_xmss.set_ots_index(a['index'])
                    if a['address'] != 'Q'+bin2hstr(tmp_xmss.address):
                        logger.fatal("Mnemonic and address do not match.")
                        exit(1)
                    self.address_dict[tmp_xmss.address] = tmp_xmss

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
                return addr_bundle.xmss.remaining_signatures()

    @staticmethod
    def get_new_address(signature_tree_height=config.dev.xmss_tree_height,
                        seed=None) -> AddressBundle:
        """
        Get a new wallet address
        The address format is a list of two items [address, data structure from random_mss call]
        :param signature_tree_height:
        :param address_type:
        :param seed:
        :return: a wallet address
        """
        # FIXME: This should be always using the extended seed instead
        if seed and signature_tree_height:
            xmss = XMSS(XmssFast(seed, signature_tree_height))
        elif seed:
            xmss = XMSS.from_extended_seed(seed)
        else:
            xmss = XMSS.from_height(signature_tree_height)

        return AddressBundle(bin2hstr(xmss.address).encode(), xmss)
