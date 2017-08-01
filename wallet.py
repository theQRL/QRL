# wallet code

__author__ = 'pete'

from merkle import sha256, mnemonic_to_seed
import merkle
import chain
import cPickle as pickle
import node
import os
import sys


class Wallet:
    def __init__(self, chain, state):
        self.chain = chain
        self.state = state

    def log(self, string_data):
        with open("./log/log.txt", "a") as myfile:
            myfile.write(string_data)
        return

    def recover_wallet(self):
        data = None
        try:
            with open('./wallet.info', 'r') as myfile:
                data = pickle.load(myfile)
            if data and len(data[0]) != 5:
                printL(('wallet.info is also corrupted, cannot recover'))
                return False
        except:
            printL(('Wallet.info is corrupted'))
            return False

        with open("./wallet.dat", "w+") as myfile:
            pass
        self.chain.my = []
        for wallets in data:
            words = wallets[0]
            addr = self.getnewaddress(type='XMSS', SEED=mnemonic_to_seed(words))
            self.f_append_wallet(addr, True)

        return True

    def f_read_wallet(self):

        addr_list = []

        if os.path.isfile('./wallet.dat') is False:
            printL(('[info] Creating new wallet file..this could take up to a minute'))
            SEED = None
            # For AWS test only
            if os.path.isfile('./mnemonic'):
                with open('./mnemonic','r') as f:
                    SEED = f.read()
                    SEED = mnemonic_to_seed(SEED.strip())

            addr_list.append(self.getnewaddress(4096, 'XMSS', SEED=SEED))
            with open("./wallet.dat", "a") as myfile:  # add in a new call to create random_otsmss
                pickle.dump(addr_list, myfile)

        while True:
            try:
                with open('./wallet.dat', 'r') as myfile:
                    return pickle.load(myfile)
            except:
                printL(('Wallet.dat corrupted'))
                printL(('Trying to recover'))
                if self.recover_wallet():
                    continue
                printL(('Failed to Recover Wallet'))
                sys.exit()

    def f_save_wallet(self):
        printL(('Syncing wallet file'))
        with open("./wallet.dat", "w+") as myfile:  # overwrites wallet..should add some form of backup to this..seed
            pickle.dump(self.chain.my, myfile)
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
        printL(('Fast saving wallet recovery details to wallet.info..'))
        with open("./wallet.info",
                  "w+") as myfile:  # stores the recovery phrase, signatures and the index for each tree in the wallet..
            pickle.dump(data, myfile)
            return

    def f_load_winfo(self):
        try:
            with open('./wallet.info', 'r') as myfile:
                data = pickle.load(myfile)
        except:
            printL(('Error: likely no wallet.info found, creating..'))
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
            printL(('Appending wallet file..'))
            with open("./wallet.dat", "w+") as myfile:  # overwrites wallet..
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

    def list_addresses(self):
        if not self.chain.my:
            addr = self.f_read_wallet()
        else:
            addr = self.chain.my

        list_addr = []
        for address in addr:
            x = 0
            y = 0
            for t in self.chain.transaction_pool:
                if t.txfrom == address[0]:
                    y += 1
                    x -= t.amount

                if t.txto == address[0]:
                    x += t.amount

            # add state check for

            if type(address[1]) == list:
                list_addr.append([address[0], 'type:', address[1][0].type, 'balance: ' + str(
                    self.state.state_balance(address[0]) / 100000000.000000000) + '(' + str(
                    self.state.state_balance(address[0]) / 100000000.000000000 + x / 100000000.000000000) + ')',
                                  'nonce:' + str(self.state.state_nonce(address[0])) + '(' + str(
                                      self.state.state_nonce(address[0]) + y) + ')', 'signatures left: ' + str(
                        address[1][0].signatures - self.state.state_nonce(address[0])) + ' (' + str(
                        address[1][0].signatures - self.state.state_nonce(address[0]) - y) + '/' + str(
                        address[1][0].signatures) + ')'])
            else:  # xmss
                list_addr.append([address[0], 'type:', address[1].type, 'balance: ' + str(
                    self.state.state_balance(address[0]) / 100000000.000000000) + '(' + str(
                    self.state.state_balance(address[0]) / 100000000.000000000 + x / 100000000.000000000) + ')',
                                  'nonce:' + str(self.state.state_nonce(address[0])) + '(' + str(
                                      self.state.state_nonce(address[0]) + y) + ')',
                                  'signatures left: ' + str(address[1].remaining) + ' (' + str(
                                      address[1].remaining) + '/' + str(address[1].signatures) + ')'])

        return list_addr

    def getnewaddress(self, signatures=4096, type='XMSS',
                      SEED=None):  # new address format is a list of two items [address, data structure from random_mss call]
        addr = []
        if type == 'XMSS':
            new = merkle.XMSS(signatures=signatures, SEED=SEED)
            addr.append(new.address)
            addr.append(new)
        elif type == 'WOTS':
            new = merkle.random_wmss(signatures=signatures)
            addr.append(self.chain.roottoaddr(new[0].merkle_root))
            addr.append(new)
        elif type == 'LDOTS':
            new = merkle.random_ldmss(signatures=signatures)
            addr.append(self.chain.roottoaddr(new[0].merkle_root))
            addr.append(new)
        else:
            raise Exception('OTS type not recognised')

        return addr

    def xmss_getnewaddress(self, signatures=4096, SEED=None,
                           type='WOTS+'):  # new address format returns a stateful XMSS class object
        return merkle.XMSS(signatures, SEED)

    def savenewaddress(self, signatures=64, type='WOTS'):
        self.f_append_wallet(self.getnewaddress(signatures, type))
