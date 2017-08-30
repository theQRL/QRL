# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# wallet code
import logger
import qrl.crypto.xmss
import transaction
from qrl.crypto import merkle
from qrl.crypto.merkle import mnemonic_to_seed

__author__ = 'pete'

import cPickle as pickle
import gc
import os
import sys

import configuration as config


class Wallet:
    ADDRESS_TYPE_XMSS = 'XMSS'
    ADDRESS_TYPE_WOTS = 'WOTS'
    ADDRESS_TYPE_LDOTS = 'LDOTS'

    def __init__(self, chain, state):
        # FIXME: state is already part of the chain
        # FIXME: Probably the wallet should own the chain, not the opposite
        self.chain = chain
        self.state = state
        self.wallet_dat_filename = os.path.join(config.user.wallet_path, config.dev.wallet_dat_filename)
        self.wallet_info_filename = os.path.join(config.user.wallet_path, config.dev.wallet_info_filename)
        self.mnemonic_filename = os.path.join(config.user.wallet_path, config.dev.mnemonic_filename)

    def recover_wallet(self):
        data = None
        try:
            with open(self.wallet_info_filename, 'r') as myfile:
                data = pickle.load(myfile)
            if data and len(data[0]) != 5:
                logger.info('wallet.info is also corrupted, cannot recover')
                return False
        except:
            logger.error('Wallet.info is corrupted')
            return False

        with open(self.wallet_dat_filename, "w+") as myfile:
            pass
        self.chain.my = []
        for wallets in data:
            words = wallets[0]
            addr = self.getnewaddress(addrtype='XMSS', SEED=mnemonic_to_seed(words))
            self.f_append_wallet(addr, True)

        return True

    def f_read_wallet(self):
        addr_list = []

        if os.path.isfile(self.wallet_dat_filename) is False:
            logger.info('Creating new wallet file... (this could take up to a minute)')
            SEED = None
            # For AWS test only
            if os.path.isfile(self.mnemonic_filename):
                with open(self.mnemonic_filename, 'r') as f:
                    SEED = f.read()
                    SEED = mnemonic_to_seed(SEED.strip())

            # addr_list.append(self.getnewaddress(4096, 'XMSS', SEED=SEED))
            addr_list.append(self.getnewaddress(8000, 'XMSS', SEED=SEED))
            with open(self.wallet_dat_filename, "a") as myfile:  # add in a new call to create random_otsmss
                pickle.dump(addr_list, myfile)

        while True:
            try:
                with open(self.wallet_dat_filename, 'r') as myfile:
                    return pickle.load(myfile)
            except:
                logger.warning('Wallet.dat corrupted')
                logger.warning('Trying to recover')
                if self.recover_wallet():
                    continue
                logger.error('Failed to Recover Wallet')
                sys.exit()

    def f_save_wallet(self):
        logger.info('Syncing wallet file')
        with open(self.wallet_dat_filename,
                  "w+") as myfile:  # overwrites wallet..should add some form of backup to this..seed
            pickle.dump(self.chain.my, myfile)
            gc.collect()
            return

    def f_save_winfo(self):
        data = []
        for tree in self.chain.my:
            if type(tree[1]) == list:
                pass
            else:
                if tree[1].type == 'XMSS':
                    data.append(
                        [tree[1].mnemonic, tree[1].hexSEED, tree[1].signatures, tree[1].index, tree[1].remaining])
        logger.info('Fast saving wallet recovery details to wallet.info..')
        # stores the recovery phrase, signatures and the index for each tree in the wallet..
        with open(self.wallet_info_filename, "w+") as myfile:
            pickle.dump(data, myfile)
            return

    def f_load_winfo(self):
        try:
            with open(self.wallet_info_filename, 'r') as myfile:
                data = pickle.load(myfile)
        except Exception as e:
            logger.exception(e)
            logger.info('Likely no wallet.info found, creating..')
            self.f_save_winfo()
            return False
        x = 0
        for tree in self.chain.my:
            if type(tree[
                        1]) == list:  # if any part of self.chain.my which has loaded from f_read_wallet() on startup is lower than winfo then don't load..
                pass
            else:
                if tree[1].index <= data[x][3]:
                    tree[1].index = data[x][3]  # update self.chain.my from winfo then save to main file..
                    tree[1].remaining = data[x][4]
                else:
                    return False
                x += 1
        self.f_save_wallet()
        return True

    def f_append_wallet(self, data, ignore_chain=False):
        if not ignore_chain:
            if not self.chain.my:
                self.chain.my = self.f_read_wallet()
        if data is not False:
            self.chain.my.append(data)
            logger.info('Appending wallet file..')
            with open(self.wallet_dat_filename, "w+") as myfile:  # overwrites wallet..
                pickle.dump(self.chain.my, myfile)
        self.f_save_winfo()
        return

    # def inspect_wallet():												# returns 3 lists of addresses, signatures and types..basic at present..
    #	data = f_read_wallet()
    #	if data is not False:
    #			num_sigs = []
    #			types = []
    #			addresses = []
    #			for x in range(len(data)):
    #				addresses.append(data[x][0])
    #				num_sigs.append(len(data[x][1]))
    #				types.append(data[x][1][0].type)
    #			return addresses, num_sigs, types
    #	return False

    def list_addresses(self, dict_format=False):
        if not self.chain.my:
            addr = self.f_read_wallet()
        else:
            addr = self.chain.my

        list_addr = []
        list_addresses = []
        count = 0
        for address in addr:
            x = 0
            y = 0
            for t in self.chain.transaction_pool:
                if t.subtype == transaction.TX_SUBTYPE_TX:
                    if t.txfrom == address[0]:
                        y += 1
                        x -= t.amount

                    if t.txto == address[0]:
                        x += t.amount

            dict_addr = {}

            # add state check for
            if type(address[1]) == list:
                dict_addr['address'] = address[0]
                dict_addr['type'] = address[1][0].type
                dict_addr['balance'] = str(
                    self.state.state_balance(address[0]) / 100000000.000000000) + ' (' + str(
                    self.state.state_balance(address[0]) / 100000000.000000000 + x / 100000000.000000000) + ')'
                dict_addr['nonce'] = str(self.state.state_nonce(address[0])) + \
                                     '(' + str(self.state.state_nonce(address[0]) + y) + ')'
                dict_addr['signatures_left'] = str(
                    address[1][0].signatures - self.state.state_nonce(address[0])) + ' (' + str(
                    address[1][0].signatures - self.state.state_nonce(address[0]) - y) + '/' + str(
                    address[1][0].signatures) + ')'
                list_addr.append([address[0], 'type:', address[1][0].type, 'balance: ' + dict_addr['balance'],
                                  'nonce:' + dict_addr['nonce'], 'signatures left: ' + dict_addr['signatures_left']])
            else:  # xmss
                dict_addr['address'] = address[0]
                dict_addr['type'] = address[1].type
                dict_addr['balance'] = str(
                    self.state.state_balance(address[0]) / 100000000.000000000) + '(' + str(
                    self.state.state_balance(address[0]) / 100000000.000000000 + x / 100000000.000000000) + ')'
                dict_addr['nonce'] = str(self.state.state_nonce(address[0])) + \
                                     '(' + str(self.state.state_nonce(address[0]) + y) + ')'
                dict_addr['signatures_left'] = str(address[1].remaining) + \
                                               ' (' + str(address[1].remaining) + '/' + str(address[1].signatures) + ')'

                list_addr.append([address[0],
                                  'type:', address[1].type,
                                  'balance: ' + dict_addr['balance'],
                                  'nonce:' + dict_addr['nonce'],
                                  'signatures left: ' + dict_addr['signatures_left']])

            dict_addr['position'] = count
            list_addresses.append(dict_addr)
            count += 1
        if dict_format:
            return list_addr, list_addresses

        return list_addr

    def get_num_signatures(self, address_to_check):
        if not self.chain.my:
            addr = self.f_read_wallet()
        else:
            addr = self.chain.my

        for address in addr:
            if address[0] == address_to_check:
                if type(address[1]) == list:
                    return address[1][0].signatures - self.state.state_nonce(address[0])
                else:  # xmss
                    return address[1].remaining

    # def getnewaddress(self, signatures=4096, type='XMSS',
    def getnewaddress(self, signatures=8000, addrtype=ADDRESS_TYPE_XMSS, SEED=None):
        """
        Get a new wallet address
        The address format is a list of two items [address, data structure from random_mss call]
        :param signatures:
        :param addrtype:
        :param SEED:
        :return: a wallet address
        """
        addr = []
        if addrtype == Wallet.ADDRESS_TYPE_XMSS:
            new = qrl.crypto.xmss.XMSS(signatures=signatures, SEED=SEED)
            addr.append(new.address)
            addr.append(new)
        elif addrtype == Wallet.ADDRESS_TYPE_WOTS:
            new = merkle.random_wmss(signatures=signatures)
            addr.append(self.chain.roottoaddr(new[0].merkle_root))
            addr.append(new)
        elif addrtype == Wallet.ADDRESS_TYPE_LDOTS:
            new = merkle.random_ldmss(signatures=signatures)
            addr.append(self.chain.roottoaddr(new[0].merkle_root))
            addr.append(new)
        else:
            raise Exception('OTS type not recognised')

        return addr

    # def xmss_getnewaddress(self, signatures=4096, SEED=None,
    def xmss_getnewaddress(self, signatures=8000, SEED=None, addrtype='WOTS+'):
        # new address format returns a stateful XMSS class object
        return qrl.crypto.xmss.XMSS(signatures, SEED)

    def savenewaddress(self, signatures=64, addrtype='WOTS', seed=None):
        self.f_append_wallet(self.getnewaddress(signatures, addrtype, seed))
