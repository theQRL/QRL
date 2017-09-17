# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from collections import namedtuple

import qrl.core.Transaction_subtypes
from qrl.core import config, logger
from qrl.crypto.mnemonic import mnemonic_to_seed
from qrl.crypto.xmss import XMSS

import cPickle as pickle
import os
import sys

SIGNATURE_TREE_HEIGHT = 13

AddressBundle = namedtuple('AddressBundle', 'address xmss')


class Wallet:
    ADDRESS_TYPE_XMSS = 'XMSS'

    def __init__(self):
        self.wallet_dat_filename = os.path.join(config.user.wallet_path, config.dev.wallet_dat_filename)
        self.wallet_info_filename = os.path.join(config.user.wallet_path, config.dev.wallet_info_filename)
        self.mnemonic_filename = os.path.join(config.user.wallet_path, config.dev.mnemonic_filename)

        self.address_bundle = self._read_wallet()

    def _recover_wallet(self):
        # type: () -> bool
        try:
            with open(self.wallet_info_filename, 'r') as myfile:
                data = pickle.load(myfile)

            if data and len(data[0]) != 5:
                logger.info('wallet.info is also corrupted, cannot recover')
                return False
        except Exception as e:
            logger.error('Wallet.info is corrupted')
            logger.exception(e)
            return False

        with open(self.wallet_dat_filename, "w+") as myfile:
            # FIXME: What is this? obsolete code?
            pass

        self.address_bundle = []
        for wallets in data:
            words = wallets[0]
            addr_bundle = self.get_new_address(addrtype='XMSS', SEED=mnemonic_to_seed(words))
            self.append_wallet(addr_bundle, True)
        return True

    def _retrieve_seed_from_mnemonic(self):
        # type: () -> Union[None, str]
        if os.path.isfile(self.mnemonic_filename):
            with open(self.mnemonic_filename, 'r') as f:
                seed_mnemonic = f.read()
                seed = mnemonic_to_seed(seed_mnemonic.strip())
            return seed
        return None

    def _read_wallet(self):
        # type: () -> List[AddressBundle]
        addr_bundle_list = []

        if os.path.isfile(self.wallet_dat_filename) is False:
            logger.info('Creating new wallet file... (this could take up to a minute)')
            seed = None

            # For AWS test only
            tmp_seed = self._retrieve_seed_from_mnemonic()
            if tmp_seed is not None:
                logger.info('Using mnemonic')
                seed = tmp_seed

            addr_bundle = self.get_new_address(SIGNATURE_TREE_HEIGHT,
                                               addrtype=Wallet.ADDRESS_TYPE_XMSS,
                                               SEED=seed)
            addr_bundle_list.append(addr_bundle)

            with open(self.wallet_dat_filename, "a") as f:  # add in a new call to create random_otsmss
                pickle.dump(addr_bundle_list, f)

        while True:
            try:
                with open(self.wallet_dat_filename, 'r') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.warning('Wallet.dat corrupted')
                logger.exception(e)

                logger.warning('Trying to recover')
                if self._recover_wallet():
                    continue

                logger.error('Failed to Recover Wallet')
                sys.exit()

    def save_wallet(self):
        # type: () -> None
        logger.info('Syncing wallet file')
        with open(self.wallet_dat_filename,
                  "w+") as myfile:  # overwrites wallet..should add some form of backup to this..seed
            pickle.dump(self.address_bundle, myfile)

    def save_winfo(self):
        # type: () -> None
        data = []
        for addr_bundle in self.address_bundle:
            # FIXME original code was odd, maintaining functionaly. Review
            if isinstance(addr_bundle.xmss, XMSS):
                data.append(
                    [addr_bundle.xmss.get_mnemonic(),
                     addr_bundle.xmss.get_hexseed(),
                     addr_bundle.xmss.get_number_signatures(),
                     addr_bundle.xmss.get_index(),
                     addr_bundle.xmss.get_remaining_signatures()])

        logger.info('Fast saving wallet recovery details to wallet.info..')
        # stores the recovery phrase, signatures and the index for each tree in the wallet..
        with open(self.wallet_info_filename, "w+") as myfile:
            pickle.dump(data, myfile)

    def load_winfo(self):
        # type: () -> bool
        try:
            if os.path.isfile(self.wallet_info_filename):
                with open(self.wallet_info_filename, 'r') as myfile:
                    data = pickle.load(myfile)
            else:
                logger.info('Likely no wallet.info found, creating..')
                self.save_winfo()
                return False
        except Exception as e:
            logger.exception(e)
            logger.info('Likely no wallet.info found, creating..')
            self.save_winfo()
            return False
        x = 0
        for addr_bundle in self.address_bundle:
            # if any part of self.chain.address_bundle which has loaded from f_read_wallet()
            # on startup is lower than winfo then don't load..
            if not isinstance(addr_bundle.xmss, list):
                if addr_bundle.xmss.get_index() <= data[x][3]:
                    # update self.chain.address_bundle from winfo then save to main file..
                    addr_bundle.xmss.set_index(data[x][3])
                else:
                    return False
                x += 1
        self.save_wallet()
        return True

    def append_wallet(self, data, ignore_chain=False):
        # type: (AddressBundle, bool) -> None
        if not ignore_chain:
            if not self.address_bundle:
                self.address_bundle = self._read_wallet()
        if data is not False:
            self.address_bundle.append(data)
            logger.info('Appending wallet file..')
            with open(self.wallet_dat_filename, "w+") as f:  # overwrites wallet..
                pickle.dump(self.address_bundle, f)
        self.save_winfo()

    def list_addresses(self, state, transaction_pool, dict_format=False):
        # FIXME: This is called from multiple places and requires external info. Refactor?
        addr_bundle_list = self.address_bundle
        if not addr_bundle_list:
            addr_bundle_list = self._read_wallet()

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
        addr_bundle_list = self.address_bundle
        if not addr_bundle_list:
            addr_bundle_list = self._read_wallet()

        for addr_bundle in addr_bundle_list:
            if addr_bundle.address == address_to_check:
                return addr_bundle.xmss.get_remaining_signatures()

    def get_new_address(self,
                        signature_tree_height=SIGNATURE_TREE_HEIGHT,
                        addrtype=ADDRESS_TYPE_XMSS,
                        SEED=None):
        # type: (int, str, str) -> AddressBundle
        """
        Get a new wallet address
        The address format is a list of two items [address, data structure from random_mss call]
        :param signature_tree_height:
        :param addrtype:
        :param SEED:
        :return: a wallet address
        """
        if addrtype == Wallet.ADDRESS_TYPE_XMSS:
            xmss = XMSS(tree_height=signature_tree_height, SEED=SEED)
            return AddressBundle(xmss.address, xmss)

        raise Exception('OTS type not recognised')
