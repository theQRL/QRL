# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import decimal
import simplejson as json
import time
from StringIO import StringIO

from twisted.internet.protocol import Protocol, connectionDone

import helper
from qrlcore import logger
from qrlcore.merkle import hexseed_to_seed, mnemonic_to_seed
from qrlcore.transaction import StakeTransaction
import configuration as config


class WalletProtocol(Protocol):
    def __init__(self):
        self.cmd_list = ['balance', 'mining', 'seed', 'hexseed', 'recoverfromhexseed',
                         'recoverfromwords', 'stakenextepoch', 'stake', 'address',
                         'wallet', 'send', 'mempool', 'getnewaddress', 'quit', 'exit',
                         'search', 'help', 'savenewaddress', 'listaddresses',
                         'getinfo', 'blockheight', 'json_block', 'reboot', 'peers']

        self.output = {'status': 1,
                       'keys': [],
                       'message': StringIO()}

        self.isJSON = False

    # Parse out passed in argument to get:
    # 1. Command ([0])
    # 1. 0-Many arguments ([1:])
    def parse_cmd(self, data):

        # Get entered line as an array of strings delimited by "space."
        # Will chomp away any extra spaces
        data = data.split()
        # Arguments include anything beyond the first index

        if len(data) != 0:  # if anything was entered

            command = data[0]
            args = None
            if len(data) > 0:  # args optional
                args = data[1:]

            if command in self.cmd_list:

                # Use switch cases when porting to a different language
                if command == 'getnewaddress':
                    self.getnewaddress(args)

                elif command == 'hexseed':
                    for x in self.factory.chain.my:
                        if type(x[1]) == list:
                            pass
                        else:
                            if x[1].type == 'XMSS':
                                self.output['status'] = 0
                                self.output['message'].write('Address: ' + x[1].address + '\r\n')
                                self.output['message'].write('Recovery seed: ' + x[1].hexSEED + '\r\n')
                                self.output['keys'] += ['Address', 'Recovery seed']
                                self.output['Address'] = x[1].address
                                self.output['Recovery seed'] = x[1].hexSEED

                elif command == 'seed':
                    for x in self.factory.chain.my:
                        if type(x[1]) == list:
                            pass
                        else:
                            if x[1].type == 'XMSS':
                                self.output['status'] = 0
                                self.output['message'].write('Address: ' + x[1].address + '\r\n')
                                self.output['message'].write('Recovery seed: ' + x[1].mnemonic + '\r\n')
                                self.output['keys'] += ['Address', 'Recovery seed']

                elif command == 'search':
                    if not args:
                        self.output['status'] = 1
                        self.output['message'].write('>>> Usage: search <txhash or Q-address>' + '\r\n')
                        return

                    tmp_output = None
                    if args[0][0] == 'Q':
                        tmp_output = json.loads(self.factory.chain.search_address(args[0]))
                        self.output['message'].write('Address: ' + str(args[0]))
                        self.output['message'].write('\r\nBalance: ' + str(tmp_output['state']['balance']))
                        self.output['message'].write('\r\nTransactions: ' + str(tmp_output['state']['transactions']))
                        for tx in tmp_output['transactions']:
                            self.output['message'].write(str(tx['txhash']))
                            self.output['message'].write(' ')
                            self.output['message'].write(str(tx['txfrom']))
                            self.output['message'].write(' ')
                            self.output['message'].write(str(tx['txto']))
                            self.output['message'].write(' ')
                            self.output['message'].write(str(tx['amount']))
                            self.output['message'].write('\r\n')
                    else:
                        tmp_output = json.loads(self.factory.chain.search_txhash(args[0]))
                        self.output['message'].write('Txnhash: ')
                        self.output['message'].write(args[0])
                        if tmp_output['status'] == 'Error':
                            self.output['message'].write('\r\n')
                            self.output['message'].write(str(tmp_output['error']))
                            self.output['message'].write('\r\n')
                            return True
                        self.output['message'].write('\r\nTimestamp: ')
                        self.output['message'].write(tmp_output['timestamp'])
                        self.output['message'].write('\r\nBlockNumber: ')
                        self.output['message'].write(tmp_output['block'])
                        self.output['message'].write('\r\nConfirmations: ')
                        self.output['message'].write(tmp_output['confirmations'])
                        self.output['message'].write('\r\nAmount: ')
                        self.output['message'].write(tmp_output['amount'])
                        self.output['message'].write('\r\n')

                    if not tmp_output:
                        self.output['status'] = 1
                        self.output['message'].write('>>> No Information available')
                        return True

                    for key in tmp_output.keys():
                        self.output['keys'] += [str(key)]
                        self.output[key] = tmp_output[key]

                    self.output['status'] = 0
                    self.output['message'].write('')

                elif command == 'json_block':

                    if not args:
                        self.output['message'].write(
                            helper.json_print_telnet(self.factory.chain.m_get_last_block()) + '\r\n')
                        return
                    try:
                        int(args[0])
                    except:
                        self.output['message'].write('>>> Try "json_block <block number>" ' + '\r\n')
                        return

                    if int(args[0]) > self.factory.chain.m_blockheight():
                        self.output['message'].write('>>> Block > Blockheight' + '\r\n')
                        return
                    self.output['status'] = 0
                    self.output['message'].write(
                        helper.json_print_telnet(self.factory.chain.m_get_block(int(args[0]))) + '\r\n')

                elif command == 'savenewaddress':
                    self.savenewaddress()

                elif command == 'recoverfromhexseed':
                    if not args or not hexseed_to_seed(args[0]):
                        self.output['message'].write('>>> Usage: recoverfromhexseed <paste in hexseed>' + '\r\n')
                        self.output['message'].write('>>> Could take up to a minute..' + '\r\n')
                        self.output['message'].write('>>> savenewaddress if Qaddress matches expectations..' + '\r\n')
                        return

                    self.output['status'] = 0
                    addr = self.factory.chain.wallet.getnewaddress(addrtype='XMSS', SEED=hexseed_to_seed(args[0]))
                    self.factory.newaddress = addr
                    self.output['message'].write('>>> Recovery address: ' + addr[1].address + '\r\n')
                    self.output['message'].write('>>> Recovery seed phrase: ' + addr[1].mnemonic + '\r\n')
                    self.output['message'].write('>>> hexSEED confirm: ' + addr[1].hexSEED + '\r\n')
                    self.output['message'].write('>>> savenewaddress if Qaddress matches expectations..' + '\r\n')

                    self.output['keys'] += ['recovery_address', 'recovery_seed_phrase', 'hexseed_confirm']
                    self.output['recovery_address'] = addr[1].address
                    self.output['recovery_seed_phrase'] = addr[1].mnemonic
                    self.output['hexseed_confirm'] = addr[1].hexSEED


                elif command == 'recoverfromwords':
                    if not args:
                        self.output['message'].write(
                            '>>> Usage: recoverfromwords <paste in 32 mnemonic words>' + '\r\n')
                        return
                    self.output['message'].write('>>> trying..this could take up to a minute..' + '\r\n')
                    if len(args) != 32:
                        self.output['message'].write(
                            '>>> Usage: recoverfromwords <paste in 32 mnemonic words>' + '\r\n')
                        return

                    args = ' '.join(args)
                    addr = self.factory.chain.wallet.getnewaddress(addrtype='XMSS', SEED=mnemonic_to_seed(args))
                    self.factory.newaddress = addr
                    self.output['status'] = 0
                    self.output['message'].write('>>> Recovery address: ' + addr[1].address + '\r\n')
                    self.output['message'].write('>>> Recovery hexSEED: ' + addr[1].hexSEED + '\r\n')
                    self.output['message'].write('>>> Mnemonic confirm: ' + addr[1].mnemonic + '\r\n')
                    self.output['message'].write('>>> savenewaddress if Qaddress matches expectations..' + '\r\n')

                    self.output['keys'] += ['recovery_address', 'recovery_hexseed', 'mnemonic_confirm']
                    self.output['recovery_address'] = addr[1].address
                    self.output['recovery_hexseed'] = addr[1].hexSEED
                    self.output['mnemonic_confirm'] = addr[1].mnemonic

                elif command == 'stake':
                    self.output['status'] = 0
                    self.output['message'].write(
                        '>> Toggling stake from: ' + str(self.factory.p2pFactory.stake) + ' to: ' + str(
                            not self.factory.p2pFactory.stake) + '\r\n')

                    self.factory.p2pFactory.stake = not self.factory.p2pFactory.stake
                    logger.info(('STAKING set to: ', self.factory.p2pFactory.stake))
                    self.output['keys'] += ['stake']
                    self.output['stake'] = self.factory.p2pFactory.stake

                elif command == 'stakenextepoch':
                    self.output['status'] = 0
                    self.output['message'].write(
                        '>>> Sending a stake transaction for address: ' + self.factory.chain.mining_address + ' to activate next epoch(' + str(
                            config.dev.blocks_per_epoch - (
                            self.factory.chain.m_blockchain[-1].blockheader.blocknumber - (
                                self.factory.chain.m_blockchain[
                                    -1].blockheader.epoch * config.dev.blocks_per_epoch))) + ' blocks time)' + '\r\n')

                    logger.info(('STAKE for address:', self.factory.chain.mining_address))
                    self.factory.p2pFactory.send_st_to_peers(
                        StakeTransaction().create(self.factory.chain.mining_address,
                                                  self.factory.chain.block_chain_buffer.height() + 1,
                                                  self.factory.chain.my[0][1],
                                                  balance=self.factory.chain.state.state_balance(
                                                      self.factory.chain.mining_address)))

                elif command == 'send':
                    self.send_tx(args)

                elif command == 'mempool':
                    self.output['status'] = 0
                    self.output['message'].write('>>> Number of transactions in memory pool: ' + str(
                        len(self.factory.chain.transaction_pool)) + '\r\n')
                    self.output['keys'] += ['txn_nos']
                    self.output['txn_nos'] = len(self.factory.chain.transaction_pool)

                elif command == 'help':
                    self.output['status'] = 0
                    self.output['message'].write(
                        '>>> QRL ledger help: try quit, wallet, send, getnewaddress, search, recoverfromhexseed, recoverfromwords, stake, stakenextepoch, mempool, json_block, seed, hexseed, getinfo, peers, or blockheight' + '\r\n')
                # removed 'hrs, hrs_check,'
                elif command == 'quit' or command == 'exit':
                    self.transport.loseConnection()

                elif command == 'listaddresses':
                    addresses, num_sigs, types = self.factory.chain.wallet.inspect_wallet()
                    self.output['status'] = 0
                    self.output['keys'] += ['addresses']
                    self.output['addresses'] = []
                    for x in range(len(addresses)):
                        self.output['message'].write(str(x) + ', ' + addresses[x] + '\r\n')
                        self.output['addresses'] += [addresses[x]]

                elif command == 'wallet':
                    self.wallet()

                elif command == 'getinfo':
                    self.output['status'] = 0
                    self.output['message'].write('>>> Version: ' + self.factory.chain.version_number + '\r\n')
                    self.output['message'].write('>>> Uptime: ' + str(time.time() - self.factory.start_time) + '\r\n')
                    self.output['message'].write(
                        '>>> Nodes connected: ' + str(len(self.factory.p2pFactory.peer_connections)) + '\r\n')
                    self.output['message'].write('>>> Staking set to: ' + str(self.factory.p2pFactory.stake) + '\r\n')
                    self.output['message'].write('>>> Sync status: ' + self.factory.p2pFactory.nodeState.state + '\r\n')

                    self.output['keys'] += ['version', 'uptime', 'nodes_connected', 'staking_status', 'sync_status']
                    self.output['version'] = self.factory.chain.version_number
                    self.output['uptime'] = str(time.time() - self.factory.start_time)
                    self.output['nodes_connected'] = str(len(self.factory.p2pFactory.peer_connections))
                    self.output['staking_status'] = str(self.factory.p2pFactory.stake)
                    self.output['sync_status'] = self.factory.p2pFactory.nodeState.state


                elif command == 'blockheight':
                    self.output['status'] = 0
                    self.output['message'].write('>>> Blockheight: ' + str(self.factory.chain.m_blockheight()) + '\r\n')
                    self.output['message'].write(
                        '>>> Headerhash: ' + self.factory.chain.m_blockchain[-1].blockheader.headerhash + '\r\n')

                    self.output['keys'] += ['blockheight', 'headerhash']
                    self.output['blockheight'] = self.factory.chain.m_blockheight()
                    self.output['headerhash'] = self.factory.chain.m_blockchain[-1].blockheader.headerhash

                elif command == 'peers':
                    self.output['status'] = 0
                    self.output['message'].write('>>> Connected Peers:\r\n')
                    self.output['keys'] += ['peers']
                    self.output['peers'] = {}
                    for peer in self.factory.p2pFactory.peer_connections:
                        self.output['message'].write(
                            '>>> ' + peer.identity + " [" + peer.version + "]  blockheight: " + str(
                                peer.blockheight) + '\r\n')
                        self.output['peers'][peer.identity] = {}
                        self.output['peers'][peer.identity]['version'] = peer.version
                        self.output['peers'][peer.identity]['blockheight'] = peer.blockheight


                elif command == 'reboot':
                    if len(args) < 1:
                        self.output['message'].write('>>> reboot <password>\r\n')
                        self.output['message'].write('>>> or\r\n')
                        self.output['message'].write('>>> reboot <password> <nonce>\r\n')
                        self.output['message'].write('>>> or\r\n')
                        self.output['message'].write('>>> reboot <password> <nonce> <trim_blocknum>\r\n')
                        return
                    json_hash, err = None, None
                    if len(args) == 3:
                        json_hash, status = self.factory.chain.generate_reboot_hash(args[0], args[1], args[2])
                        self.output['message'].write(str(args[0]) + str(args[1]) + str(args[2]))
                    elif len(args) == 2:
                        json_hash, status = self.factory.chain.generate_reboot_hash(args[0], args[1])
                    else:
                        json_hash, status = self.factory.chain.generate_reboot_hash(args[0])

                    if json_hash:
                        self.factory.p2pFactory.send_reboot(json_hash)
                        # self.factory.state.update('synced')
                    self.output['message'].write(status)

        else:
            return False

        return True

    def parse(self, data):
        return data.strip()

    # Called when a command is recieved through telnet
    # Might be a good idea to use a json encrypted wallet
    def dataReceived(self, data):
        self.factory.recn += 1
        self.isJSON = False
        if data.lower().startswith('json '):
            self.isJSON = True
            data = data[5:]
        try:
            if not self.parse_cmd(self.parse(data)):
                self.output['status'] = 1
                self.output['message'].write(">>> Command not recognised. Use 'help' for details" + '\r\n')
        except Exception as e:
            self.output['message'] = StringIO()
            self.output['message'].write('Unexpected Error\r\nReport to QRL Developers')
            logger.error('Unexpected Error WalletProtocol\n')
            logger.exception(e)

        self.output['message'] = self.output['message'].getvalue()

        try:
            if self.isJSON:
                self.transport.write(json.dumps(self.output))
            else:
                self.transport.write(self.output['message'])
        except Exception as e:
            logger.error('Walletprotocol unexpected exception while sending msg to client')
            logger.exception(e)
            pass

        del self.output
        self.output = {'status': 1,
                       'keys': [],
                       'message': StringIO()}

    # What does this do?
    # whenever you type telnet 127.0.0.1 2000
    # a connection is made and this function is called to initialize the things.
    def connectionMade(self):
        self.transport.write('QRL node connection established. Try starting with "help" ')
        self.factory.connections += 1
        if self.factory.connections > 1:
            logger.info('only one local connection allowed')
            self.transport.write('only one local connection allowed, sorry')
            self.transport.loseConnection()
        else:
            if self.transport.getPeer().host == '127.0.0.1':
                logger.info('>>> new local connection %s %s', str(self.factory.connections), self.transport.getPeer())
            else:
                self.transport.loseConnection()
                logger.info('Unauthorised remote login attempt..')

    def connectionLost(self, reason=connectionDone):
        self.factory.connections -= 1

        ###################################### LOCAL WALLET ACCESS ###############################################

    # Pseudocode:

    # is chain up to date? If not, fail/inform user
    # is address null/void? If it is, fail/print usage instructions
    # is the first letter of the address Q? If not, fail/print usage instructions
    # is the address in use? If not, fail/inform user

    # if all of these are met, return the balance
    def getbalance(self, addr):
        self.output['status'] = 1

        # is chain up to date? If not, fail/inform user
        if self.factory.state.state_uptodate(self.factory.chain.height()) is False:
            self.output['message'].write('>>> LevelDB not up to date..' + '\r\n')
            # add "force" argument to bring it up to date and get balance?
            return

        # is address null/void? If it is, fail/print usage instructions
        if not addr:
            self.output['message'].write('>>> Usage: getbalance <address> (Addresses begin with Q)' + '\r\n')
            return

        # is the first letter of the address Q? If not, fail/print usage instructions
        if addr[0][0] != 'Q':
            self.output['message'].write('>>> Usage: getbalance <address> (Addresses begin with Q)' + '\r\n')
            return

        # is the address in use? If not, fail/inform user
        if self.factory.state.state_address_used(addr[0]) is False:
            self.output['message'].write('>>> Unused address: ' + addr + '\r\n')
            return

        # if all of these are met, return the balance
        self.output['status'] = 0
        balance = self.factory.state.state_balance(addr[0])
        self.output['message'].write('>>> balance:  ' + str(balance) + '\r\n')
        self.output['keys'] += ['balance']
        self.output['balance'] = balance
        return

    # Pseudocode:
    # If no arguments are used, or more than 3 are used, fail/inform user of usage
    # else:
    #	get signature type to use, reject if the type is incorrect
    #   prevent user from generating an extremely large number of XMSS signatures
    #	generate address
    #	inform user of address information
    #	tell them how to save the address to wallet file
    def getnewaddress(self, args):
        self.output['status'] = 1
        if not args or len(args) > 2:
            self.output['message'].write('>>> Command not recognised' + '\r\n')
            self.output['message'].write('>>> Usage: getnewaddress <n bits> <type (XMSS, WOTS or LDOTS)>' + '\r\n')
            self.output['message'].write('>>> i.e. getnewaddress 4096 XMSS' + '\r\n')
            self.output['message'].write('>>> or: getnewaddress 128 LDOTS' + '\r\n')
            return
        else:
            try:
                # Check to see if args[0] is an integer string
                int(args[0])
            except:
                self.output['message'].write(
                    '>>> Invalid number of signatures. Usage: getnewaddress <n signatures> <type (XMSS, WOTS or LDOTS)>' + '\r\n')
                self.output['message'].write('>>> i.e. getnewaddress 4096 XMSS' + '\r\n')
                return

        # signature type to use
        sig_type = args[1].upper()
        if sig_type != 'XMSS' and sig_type != 'WOTS' and sig_type != 'LDOTS' and sig_type != 'LD':
            self.output['message'].write(
                '>>> Invalid signature address type. Usage: getnewaddress <n> <type (XMSS, WOTS or LDOTS)>' + '\r\n')
            self.output['message'].write('>>> i.e. getnewaddress 4096 XMSS' + '\r\n')
            return

        if int(args[0]) > 256 and args[1] != 'XMSS':
            # TODO:
            # You are trying to generate an extremely large number of signatures. Are you sure about this?
            # Y/N
            self.output['message'].write(
                '>>> Try a lower number of signatures or you may be waiting a very long time...' + '\r\n')
            return

        self.output['status'] = 0
        self.output['message'].write(
            '>>> Creating new address, please be patient as this can take some time ...' + '\r\n')
        self.output['keys'] += ['keypair_type', 'possible_signatures', 'address']

        addr = self.factory.chain.wallet.getnewaddress(int(args[0]), args[1])
        if type(addr[1]) == list:
            self.output['message'].write('>>> Keypair type: ' + ''.join(addr[1][0].type + '\r\n'))
            self.output['message'].write('>>> Signatures possible with address: ' + str(len(addr[1])) + '\r\n')
            self.output['message'].write('>>> Address: ' + ''.join(addr[0]) + '\r\n')

            self.output['keypair_type'] = ''.join(addr[1][0].type + '\r\n')
            self.output['possible_signatures'] = str(len(addr[1]))
            self.output['address'] = ''.join(addr[0])

        else:  # xmss
            self.output['message'].write('>>> Keypair type: ' + ''.join(addr[1].type + '\r\n'))
            self.output['message'].write('>>> Signatures possible with address: ' + str(addr[1].signatures) + '\r\n')
            self.output['message'].write('>>> Address: ' + addr[1].address + '\r\n')

            self.output['keypair_type'] = ''.join(addr[1].type + '\r\n')
            self.output['possible_signatures'] = str(addr[1].signatures)
            self.output['address'] = addr[1].address

        # TODO: Would you like to save this address to your wallet file (call savenewaddress)? Y/N
        self.output['message'].write(">>> type 'savenewaddress' to append to wallet file" + '\r\n')
        self.factory.newaddress = addr

        return

    # Simply saves wallet information
    def savenewaddress(self):
        self.output['status'] = 1
        if not self.factory.newaddress:
            self.output['message'].write(">>> No new addresses created, yet. Try 'getnewaddress'" + '\r\n')
            return
        self.output['status'] = 0
        self.factory.chain.wallet.f_append_wallet(self.factory.newaddress)
        self.output['message'].write('>>> new address saved in self.factory.chain.wallet.' + '\r\n')
        return

    # This method is for sending between local wallets as well as network wallets
    def send_tx(self, args):
        self.output['status'] = 1
        # Check if method was used correctly
        if not args or len(args) < 3:
            self.output['message'].write('>>> Usage: send <from> <to> <amount>' + '\r\n')
            self.output['message'].write('>>> i.e. send 0 4 100' + '\r\n')
            self.output['message'].write('>>> ^ will send 100 coins from address 0 to 4 from the wallet' + '\r\n')
            self.output['message'].write('>>> <to> can be a pasted address (starts with Q)' + '\r\n')
            return

        wallet_from = args[0]
        wallet_to = args[1]

        # Check if the wallet entered is a local wallet (should be, since sender should be local - it's you)
        try:
            int(wallet_from)
        except:
            self.output['message'].write(
                '>>> Invalid sending address. Try a valid number from your wallet - type wallet for details.' + '\r\n')
            return

        # Check if local wallet number is higher than the number of local wallets that are saved
        if int(wallet_from) > len(self.factory.chain.wallet.list_addresses()) - 1:
            self.output['message'].write(
                '>>> Invalid sending address. Try a valid number from your wallet - type wallet for details.' + '\r\n')
            return

        # perhaps make a "wallet_precondition(wallet)" method
        # to check if the wallet string is correct
        # good way to centralize that code too
        # in case it ever changes

        # if wallet_to is not a local wallet, and wallet_to is not prepended by Q and
        if len(wallet_to) > 1 and wallet_to[0] != 'Q' and self.factory.state.state_hrs(wallet_to) != False:
            pass
        elif wallet_to[0] == 'Q':
            pass
        else:
            try:
                int(wallet_to)
            except:
                self.output['message'].write(
                    '>>> Invalid receiving address - addresses must start with Q. Try a number from your self.factory.chain.wallet.' + '\r\n')
                return
            if int(wallet_to) > len(self.factory.chain.wallet.list_addresses()) - 1:
                self.output['message'].write(
                    '>>> Invalid receiving address - addresses must start with Q. Try a number from your self.factory.chain.wallet.' + '\r\n')
                return
            wallet_to = int(wallet_to)

        # Check to see if sending amount > amount owned (and reject if so)
        # This is hard to interpret. Break it up?
        balance = self.factory.state.state_balance(self.factory.chain.my[int(wallet_from)][0])
        send_amt_arg = args[2]
        try:
            float(send_amt_arg)
        except:
            self.output['message'].write(
                '>>> Invalid amount type. Type a number (less than or equal to the balance of the sending address)' + '\r\n')
            return

        amount = decimal.Decimal(decimal.Decimal(send_amt_arg) * 100000000).quantize(decimal.Decimal('1'),
                                                                                     rounding=decimal.ROUND_HALF_UP)

        if balance < amount:
            self.output['message'].write(
                '>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address' + '\r\n')
            self.output['message'].write(
                '>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address' + '\r\n')
            return

        # Stop user from sending less than their entire balance if they've only
        # got one signature remaining.
        sigsremaining = self.factory.chain.wallet.get_num_signatures(self.factory.chain.my[int(args[0])][0])
        if sigsremaining is 1:
            if amount < balance:
                self.output['message'].write(
                    '>>> Stop! You only have one signing signature remaining. You should send your entire balance or the remainder will be lost!' + '\r\n')
                return
        txto = args[1]
        if txto.isdigit():
            txto = int(txto)
        tx = self.factory.chain.create_my_tx(txfrom=int(args[0]), txto=txto, amount=amount)

        if tx is False:
            self.output['message'].write('Failed to Create txn')
            return

        if tx.validate_tx():
            block_chain_buffer = self.factory.chain.block_chain_buffer
            tx_state = block_chain_buffer.get_stxn_state(blocknumber=block_chain_buffer.height(),
                                                         addr=tx.txfrom)
            if not tx.state_validate_tx(tx_state=tx_state,
                                        transaction_pool=self.factory.chain.transaction_pool):
                self.output['message'].write('>>> OTS key reused')
                return
        else:
            self.output['message'].write('>>> TXN failed at validate_tx')
            logger.info('>>> TXN failed at validate_tx')
            return

        # send the transaction to peers (ie send it to the network - we are done)
        self.factory.p2pFactory.send_tx_to_peers(tx)
        self.output['status'] = 0
        self.output['message'].write('>>> ' + str(tx.txhash))
        self.output['message'].write('>>> From: ' + str(tx.txfrom) + ' To: ' + str(tx.txto) + ' For: ' + str(
            tx.amount / 100000000.000000000) + '\r\n' + '>>>created and sent into p2p network' + '\r\n')
        return

    def wallet(self):
        if not self.factory.state.state_uptodate(self.factory.chain.height()):
            self.factory.state.state_read_chain(self.factory.chain)

        self.output['status'] = 0
        self.output['message'].write('>>> Wallet contents:' + '\r\n')
        self.output['keys'] += ['list_addresses']
        self.output['list_addresses'] = {}

        list_addr, list_addresses = self.factory.chain.wallet.list_addresses(True)
        self.output['list_addresses'] = list_addresses

        y = 0
        for address in list_addr:
            self.output['message'].write(str(y) + str(address) + '\r\n')
            y += 1
