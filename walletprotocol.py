from twisted.internet.protocol import ServerFactory, Protocol
from transaction import StakeTransaction
import decimal
import configuration as c
import helper
import time
from merkle import hexseed_to_seed, mnemonic_to_seed


class WalletProtocol(Protocol):
    def __init__(self):
        self.cmd_list = ['balance', 'mining', 'seed', 'hexseed', 'recoverfromhexseed',
                         'recoverfromwords', 'stakenextepoch', 'stake', 'address',
                         'wallet', 'send', 'mempool', 'getnewaddress', 'quit', 'exit',
                         'search', 'json_search', 'help', 'savenewaddress', 'listaddresses',
                         'getinfo', 'blockheight', 'json_block', 'reboot', 'peers']

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
            args=None
            if len(data)>0:  # args optional
                args = data[1:]

            if command in self.cmd_list:

                # Use switch cases when porting to a different language
                if command == 'getnewaddress':
                    self.getnewaddress(args)
                    return

                if command == 'hexseed':
                    for x in self.factory.chain.my:
                        if type(x[1]) == list:
                            pass
                        else:
                            if x[1].type == 'XMSS':
                                self.transport.write('Address: ' + x[1].address + '\r\n')
                                self.transport.write('Recovery seed: ' + x[1].hexSEED + '\r\n')
                    return

                if command == 'seed':
                    for x in self.factory.chain.my:
                        if type(x[1]) == list:
                            pass
                        else:
                            if x[1].type == 'XMSS':
                                self.transport.write('Address: ' + x[1].address + '\r\n')
                                self.transport.write('Recovery seed: ' + x[1].mnemonic + '\r\n')
                    return

                elif command == 'search':
                    if not args:
                        self.transport.write('>>> Usage: search <txhash or Q-address>' + '\r\n')
                        return
                    for result in self.factory.chain.search_telnet(args[0], long=0):
                        self.transport.write(str(result) + '\r\n')
                    return

                elif command == 'json_search':
                    if not args:
                        self.transport.write('>>>Usage: search <txhash or Q-address>' + '\r\n')
                        return
                    for result in self.factory.chain.search_telnet(args[0], long=1):
                        self.transport.write(result + '\r\n')
                    return

                elif command == 'json_block':

                    if not args:
                        # chain.json_printL(((chain.m_get_last_block())
                        self.transport.write(helper.json_print_telnet(self.factory.chain.m_get_last_block()) + '\r\n')
                        return
                    try:
                        int(args[0])
                    except:
                        self.transport.write('>>> Try "json_block <block number>" ' + '\r\n')
                        return

                    if int(args[0]) > self.factory.chain.m_blockheight():
                        self.transport.write('>>> Block > Blockheight' + '\r\n')
                        return

                    self.transport.write(
                        helper.json_print_telnet(self.factory.chain.m_get_block(int(args[0]))) + '\r\n')
                    return

                elif command == 'savenewaddress':
                    self.savenewaddress()

                elif command == 'recoverfromhexseed':
                    if not args or not hexseed_to_seed(args[0]):
                        self.transport.write('>>> Usage: recoverfromhexseed <paste in hexseed>' + '\r\n')
                        self.transport.write('>>> Could take up to a minute..' + '\r\n')
                        self.transport.write('>>> savenewaddress if Qaddress matches expectations..' + '\r\n')
                        return

                    self.transport.write('>>> trying.. this could take up to a minute..' + '\r\n')
                    addr = self.factory.chain.wallet.getnewaddress(type='XMSS', SEED=hexseed_to_seed(args[0]))
                    self.factory.newaddress = addr
                    self.transport.write('>>> Recovery address: ' + addr[1].address + '\r\n')
                    self.transport.write('>>> Recovery seed phrase: ' + addr[1].mnemonic + '\r\n')
                    self.transport.write('>>> hexSEED confirm: ' + addr[1].hexSEED + '\r\n')
                    self.transport.write('>>> savenewaddress if Qaddress matches expectations..' + '\r\n')
                    return

                elif command == 'recoverfromwords':
                    if not args:
                        self.transport.write('>>> Usage: recoverfromwords <paste in 32 mnemonic words>' + '\r\n')
                        return
                    self.transport.write('>>> trying..this could take up to a minute..' + '\r\n')
                    if len(args) != 32:
                        self.transport.write('>>> Usage: recoverfromwords <paste in 32 mnemonic words>' + '\r\n')
                        return
                    args = ' '.join(args)
                    addr = self.factory.chain.wallet.getnewaddress(type='XMSS', SEED=mnemonic_to_seed(args))
                    self.factory.newaddress = addr
                    self.transport.write('>>> Recovery address: ' + addr[1].address + '\r\n')
                    self.transport.write('>>> Recovery hexSEED: ' + addr[1].hexSEED + '\r\n')
                    self.transport.write('>>> Mnemonic confirm: ' + addr[1].mnemonic + '\r\n')
                    self.transport.write('>>> savenewaddress if Qaddress matches expectations..' + '\r\n')
                    return

                elif command == 'stake':
                    self.transport.write(
                        '>> Toggling stake from: ' + str(self.factory.p2pFactory.stake) + ' to: ' + str(
                            not self.factory.p2pFactory.stake) + '\r\n')
                    self.factory.p2pFactory.stake = not self.factory.p2pFactory.stake
                    printL(('STAKING set to: ', self.factory.p2pFactory.stake))
                    return

                elif command == 'stakenextepoch':
                    self.transport.write(
                        '>>> Sending a stake transaction for address: ' + self.factory.chain.mining_address + ' to activate next epoch(' + str(
                            c.blocks_per_epoch - (self.factory.chain.m_blockchain[-1].blockheader.blocknumber - (
                                self.factory.chain.m_blockchain[
                                    -1].blockheader.epoch * c.blocks_per_epoch))) + ' blocks time)' + '\r\n')
                    printL(('STAKE for address:', self.factory.chain.mining_address))
                    self.factory.p2pFactory.send_st_to_peers(
                        StakeTransaction().create_stake_transaction(self.factory.chain.mining_address,
                                                                    self.factory.chain.block_chain_buffer.height() + 1,
                                                                    self.factory.chain.my[0][1],
                                                                    balance=self.factory.chain.state.state_balance(
                                                                        self.factory.chain.mining_address)))
                    return

                elif command == 'send':
                    self.send_tx(args)

                elif command == 'mempool':
                    self.transport.write('>>> Number of transactions in memory pool: ' + str(
                        len(self.factory.chain.transaction_pool)) + '\r\n')

                elif command == 'help':
                    self.transport.write(
                        '>>> QRL ledger help: try quit, wallet, send, getnewaddress, search, recoverfromhexseed, recoverfromwords, stake, stakenextepoch, mempool, json_block, json_search, seed, hexseed, getinfo, peers, or blockheight' + '\r\n')
                # removed 'hrs, hrs_check,'
                elif command == 'quit' or command == 'exit':
                    self.transport.loseConnection()

                elif command == 'listaddresses':
                    addresses, num_sigs, types = self.factory.chain.wallet.inspect_wallet()

                    for x in range(len(addresses)):
                        self.transport.write(str(x) + ', ' + addresses[x] + '\r\n')

                elif command == 'wallet':
                    self.wallet()

                elif command == 'getinfo':
                    self.transport.write('>>> Version: ' + self.factory.chain.version_number + '\r\n')
                    self.transport.write('>>> Uptime: ' + str(time.time() - self.factory.start_time) + '\r\n')
                    self.transport.write('>>> Nodes connected: ' + str(len(self.factory.p2pFactory.peers)) + '\r\n')
                    self.transport.write('>>> Staking set to: ' + str(self.factory.p2pFactory.stake) + '\r\n')
                    self.transport.write('>>> Sync status: ' + self.factory.p2pFactory.nodeState.state + '\r\n')

                elif command == 'blockheight':
                    self.transport.write('>>> Blockheight: ' + str(self.factory.chain.m_blockheight()) + '\r\n')
                    self.transport.write(
                        '>>> Headerhash: ' + self.factory.chain.m_blockchain[-1].blockheader.headerhash + '\r\n')

                elif command == 'peers':
                    self.transport.write('>>> Connected Peers:\r\n')
                    for peer in self.factory.p2pFactory.peers:
                        self.transport.write('>>> ' + peer.identity + " [" + peer.version + "]  blockheight: " + str(
                            peer.blockheight) + '\r\n')

                elif command == 'reboot':
                    if len(args) < 1:
                        self.transport.write('>>> reboot <password>\r\n')
                        self.transport.write('>>> or\r\n')
                        self.transport.write('>>> reboot <password> <nonce>\r\n')
                        self.transport.write('>>> or\r\n')
                        self.transport.write('>>> reboot <password> <nonce> <trim_blocknum>\r\n')
                        return
                    json_hash, err = None, None
                    if len(args) == 3:
                        json_hash, status = self.factory.chain.generate_reboot_hash(args[0], args[1], args[2])
                        self.transport.write(str(args[0]) + str(args[1]) + str(args[2]))
                    elif len(args) == 2:
                        json_hash, status = self.factory.chain.generate_reboot_hash(args[0], args[1])
                    else:
                        json_hash, status = self.factory.chain.generate_reboot_hash(args[0])

                    if json_hash:
                        self.factory.p2pFactory.send_reboot(json_hash)
                        # self.factory.state.update('synced')
                    self.transport.write(status)

        else:
            return False

        return True

    # Silly
    def parse(self, data):
        return data.strip()

    # Called when a command is recieved through telnet
    # Might be a good idea to use a json encrypted wallet
    def dataReceived(self, data):
        self.factory.recn += 1
        if self.parse_cmd(self.parse(data)) == False:
            self.transport.write(">>> Command not recognised. Use 'help' for details" + '\r\n')

    # What does this do?
    # whenever you type telnet 127.0.0.1 2000
    # a connection is made and this function is called to initialize the things.
    def connectionMade(self):
        self.transport.write('QRL node connection established. Try starting with "help" ')
        self.factory.connections += 1
        if self.factory.connections > 1:
            printL(('only one local connection allowed'))
            self.transport.write('only one local connection allowed, sorry')
            self.transport.loseConnection()
        else:
            if self.transport.getPeer().host == '127.0.0.1':
                printL(('>>> new local connection', str(self.factory.connections), self.transport.getPeer()))
            # welcome functions to run here..
            else:
                self.transport.loseConnection()
                printL(('Unauthorised remote login attempt..'))

    def connectionLost(self, reason):
        self.factory.connections -= 1

        ###################################### LOCAL WALLET ACCESS ###############################################

    # Pseudocode:

    # is chain up to date? If not, fail/inform user
    # is address null/void? If it is, fail/print usage instructions
    # is the first letter of the address Q? If not, fail/print usage instructions
    # is the address in use? If not, fail/inform user

    # if all of these are met, return the balance
    def getbalance(self, addr):

        # is chain up to date? If not, fail/inform user
        if self.factory.state.state_uptodate(self.factory.chain.height()) is False:
            self.transport.write('>>> LevelDB not up to date..' + '\r\n')
            # add "force" argument to bring it up to date and get balance?
            return

        # is address null/void? If it is, fail/print usage instructions
        if not addr:
            self.transport.write('>>> Usage: getbalance <address> (Addresses begin with Q)' + '\r\n')
            return

        # is the first letter of the address Q? If not, fail/print usage instructions
        if addr[0][0] != 'Q':
            self.transport.write('>>> Usage: getbalance <address> (Addresses begin with Q)' + '\r\n')
            return

        # is the address in use? If not, fail/inform user
        if self.factory.state.state_address_used(addr[0]) is False:
            self.transport.write('>>> Unused address: ' + addr + '\r\n')
            return

        # if all of these are met, return the balance
        self.transport.write('>>> balance:  ' + str(self.factory.state.state_balance(addr[0])) + '\r\n')
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
        if not args or len(args) > 2:
            self.transport.write('>>> Usage: getnewaddress <n bits> <type (XMSS, WOTS or LDOTS)>' + '\r\n')
            self.transport.write('>>> i.e. getnewaddress 4096 XMSS' + '\r\n')
            self.transport.write('>>> or: getnewaddress 128 LDOTS' + '\r\n')
            self.transport.write('>>> (new address creation can take a while, please be patient..)' + '\r\n')
            return
        else:
            try:
                # Check to see if args[0] is an integer string
                int(args[0])
            except:
                self.transport.write(
                    '>>> Invalid number of signatures. Usage: getnewaddress <n signatures> <type (XMSS, WOTS or LDOTS)>' + '\r\n')
                self.transport.write('>>> i.e. getnewaddress 4096 XMSS' + '\r\n')
                return

        # signature type to use
        sig_type = args[1].upper()
        if sig_type != 'XMSS' and sig_type != 'WOTS' and sig_type != 'LDOTS' and sig_type != 'LD':
            self.transport.write(
                '>>> Invalid signature address type. Usage: getnewaddress <n> <type (XMSS, WOTS or LDOTS)>' + '\r\n')
            self.transport.write('>>> i.e. getnewaddress 4096 XMSS' + '\r\n')
            return

        if int(args[0]) > 256 and args[1] != 'XMSS':
            # TODO:
            # You are trying to generate an extremely large number of signatures. Are you sure about this?
            # Y/N
            self.transport.write(
                '>>> Try a lower number of signatures or you may be waiting a very long time...' + '\r\n')
            return

        self.transport.write('>>> Creating address..please wait' + '\r\n')
        addr = self.factory.chain.wallet.getnewaddress(int(args[0]), args[1])

        if type(addr[1]) == list:
            self.transport.write('>>> Keypair type: ' + ''.join(addr[1][0].type + '\r\n'))
            self.transport.write('>>> Signatures possible with address: ' + str(len(addr[1])) + '\r\n')
            self.transport.write('>>> Address: ' + ''.join(addr[0]) + '\r\n')

        else:  # xmss
            self.transport.write('>>> Keypair type: ' + ''.join(addr[1].type + '\r\n'))
            self.transport.write('>>> Signatures possible with address: ' + str(addr[1].signatures) + '\r\n')
            self.transport.write('>>> Address: ' + addr[1].address + '\r\n')

        # TODO: Would you like to save this address to your wallet file (call savenewaddress)? Y/N
        self.transport.write(">>> type 'savenewaddress' to append to wallet file" + '\r\n')
        self.factory.newaddress = addr

        return

    # Simply saves wallet information
    def savenewaddress(self):
        if not self.factory.newaddress:
            self.transport.write(">>> No new addresses created, yet. Try 'getnewaddress'" + '\r\n')
            return
        self.factory.chain.wallet.f_append_wallet(self.factory.newaddress)
        self.transport.write('>>> new address saved in self.factory.chain.wallet.' + '\r\n')
        return

    # This method is for sending between local wallets as well as network wallets
    def send_tx(self, args):

        # Check if method was used correctly
        if not args or len(args) < 3:
            self.transport.write('>>> Usage: send <from> <to> <amount>' + '\r\n')
            self.transport.write('>>> i.e. send 0 4 100' + '\r\n')
            self.transport.write('>>> ^ will send 100 coins from address 0 to 4 from the wallet' + '\r\n')
            self.transport.write('>>> <to> can be a pasted address (starts with Q)' + '\r\n')
            return

        wallet_from = args[0]
        wallet_to = args[1]

        # Check if the wallet entered is a local wallet (should be, since sender should be local - it's you)
        try:
            int(wallet_from)
        except:
            self.transport.write(
                '>>> Invalid sending address. Try a valid number from your wallet - type wallet for details.' + '\r\n')
            return

        # Check if local wallet number is higher than the number of local wallets that are saved
        if int(wallet_from) > len(self.factory.chain.wallet.list_addresses()) - 1:
            self.transport.write(
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
                self.transport.write(
                    '>>> Invalid receiving address - addresses must start with Q. Try a number from your self.factory.chain.wallet.' + '\r\n')
                return
            if int(wallet_to) > len(self.factory.chain.wallet.list_addresses()) - 1:
                self.transport.write(
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
            self.transport.write(
                '>>> Invalid amount type. Type a number (less than or equal to the balance of the sending address)' + '\r\n')
            return

        amount = decimal.Decimal(decimal.Decimal(send_amt_arg) * 100000000).quantize(decimal.Decimal('1'),
                                                                                     rounding=decimal.ROUND_HALF_UP)

        if balance < amount:
            self.transport.write(
                '>>> Invalid amount to send. Type a number less than or equal to the balance of the sending address' + '\r\n')
            return

        # Stop user from sending less than their entire balance if they've only
        # got one signature remaining.
        sigsremaining = self.factory.chain.wallet.get_num_signatures(self.factory.chain.my[int(args[0])][0])
        if sigsremaining is 1:
            if amount < balance:
                self.transport.write(
                    '>>> Stop! You only have one signing signature remaining. You should send your entire balance or the remainder will be lost!' + '\r\n')
                return

        tx = self.factory.chain.create_my_tx(txfrom=int(args[0]), txto=args[1], amount=amount)

        if tx is False:
            # print error here?
            return

        if tx.validate_tx():
            if not tx.state_validate_tx(state=self.factory.state, transaction_pool=self.factory.chain.transaction_pool):
                self.transport.write('>>> OTS key reused')
                return
        else:
            self.transport.write('>>> TXN failed at validate_tx')
            printL(('>>> TXN failed at validate_tx'))
            return

        # send the transaction to peers (ie send it to the network - we are done)
        self.factory.p2pFactory.send_tx_to_peers(tx)
        self.transport.write('>>> ' + str(tx.txhash))
        self.transport.write('>>> From: ' + str(tx.txfrom) + ' To: ' + str(tx.txto) + ' For: ' + str(
            tx.amount / 100000000.000000000) + '\r\n' + '>>>created and sent into p2p network' + '\r\n')
        return

    def wallet(self):
        if self.factory.state.state_uptodate(self.factory.chain.height()) == False:
            self.factory.state.state_read_chain(self.factory.chain)
        self.transport.write('>>> Wallet contents:' + '\r\n')
        y = 0
        for address in self.factory.chain.wallet.list_addresses():
            self.transport.write(str(y) + str(address) + '\r\n')
            y += 1


class WalletFactory(ServerFactory):
    def __init__(self, stuff, chain, state, p2pFactory):
        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.protocol = WalletProtocol
        self.newaddress = 0
        self.stuff = stuff
        self.recn = 0
        self.maxconnections = 1
        self.connections = 0
        self.start_time = time.time()
        self.last_cmd = 'help'
