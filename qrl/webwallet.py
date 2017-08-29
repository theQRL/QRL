# QRL Web Wallet
# localhost:8888/
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from core.merkle import mnemonic_to_seed, hexseed_to_seed

import decimal
import json
import os

from twisted.internet import reactor, endpoints
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web.static import File

from core import helper, wallet

__author__ = 'scottdonaldau'

class WebWallet:
    def __init__(self, chain, state, p2pFactory):
        # Get working directory
        cwd = os.getcwd()

        self.cwd = cwd
        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.wallet = wallet.Wallet(self.chain, self.state)

        # Start local web server and define routes
        resource = File(self.cwd + '/qrl/web-wallet')
        resource.putChild("webwallet-addresses", showAddresses(self.wallet))
        resource.putChild("webwallet-create-new-address", newAddress(self.wallet))
        resource.putChild("webwallet-send", sendQuanta(self.chain, self.state, self.p2pFactory))
        resource.putChild("webwallet-mempool", memPoolSize(self.chain))
        resource.putChild("webwallet-sync", syncStatus(self.p2pFactory))
        resource.putChild("webwallet-recover", recoverAddress(self.wallet, self.chain))

        factory = Site(resource)
        endpoint = endpoints.TCP4ServerEndpoint(reactor, 8888, interface='127.0.0.1')
        endpoint.listen(factory)


class showAddresses(Resource):
    def __init__(self, Wallet):
        Resource.__init__(self)
        self.wallet = Wallet

    isLeaf = True

    def render_GET(self, request):
        return helper.json_encode(self.wallet.list_addresses())


class newAddress(Resource):
    def __init__(self, Wallet):
        Resource.__init__(self)
        self.wallet = Wallet

    isLeaf = True

    def render_GET(self, request):
        return self.wallet.savenewaddress(signatures=8000, addrtype='XMSS')


class recoverAddress(Resource):
    def __init__(self, Wallet, Chain):
        Resource.__init__(self)
        self.wallet = Wallet
        self.chain = Chain
        self.result = {}

    isLeaf = True

    def render_POST(self, request):
        req = request.content.read()
        jsQ = json.loads(req)

        self.result = {
            'status': 'fail',
            'message': '',
            'recoveredAddress': '',
            'hexseed': '',
            'mnemonic': ''
        }

        # Recover address from mnemonic
        if jsQ["type"] == "mnemonic":
            # Fail if no words provided
            if not jsQ["words"]:
                self.result["message"] = "You must provide your mnemonic phrase!"
                return helper.json_encode(self.result)

            mnemonicphrase = jsQ["words"]
            words = mnemonicphrase.split()
            if len(words) != 32:
                self.result["message"] = "Invalid mnemonic phrase! It must be 32 words exactly"
                return helper.json_encode(self.result)

            # Try to recover
            try:
                addr = self.wallet.savenewaddress(signatures=8000, addrtype='XMSS',
                                                  seed=mnemonic_to_seed(mnemonicphrase))

                # Find hex/mnemonic for recovered wallet
                for x in self.chain.my:
                    if type(x[1]) == list:
                        pass
                    else:
                        if x[1].type == 'XMSS' and x[1].mnemonic == mnemonicphrase:
                            self.result["recoveredAddress"] = x[1].address
                            self.result["hexseed"] = x[1].hexSEED
                            self.result["mnemonic"] = x[1].mnemonic
            except:
                self.result[
                    "message"] = "There was a problem restoring your address. If you believe this is in error, please raise it with the QRL team."
                return helper.json_encode(self.result)

        # Recover address from hexseed
        elif jsQ["type"] == "hexseed":
            if not jsQ["hexseed"] or not hexseed_to_seed(jsQ["hexseed"]):
                self.result["message"] = "Invalid Hex Seed!"
                return helper.json_encode(self.result)

            # Try to recover
            try:
                addr = self.wallet.savenewaddress(signatures=8000, addrtype='XMSS',
                                                  seed=hexseed_to_seed(jsQ["hexseed"]))

                # Find hex/mnemonic for recovered wallet
                for x in self.chain.my:
                    if type(x[1]) == list:
                        pass
                    else:
                        if x[1].type == 'XMSS' and x[1].hexSEED == jsQ["hexseed"]:
                            self.result["recoveredAddress"] = x[1].address
                            self.result["hexseed"] = x[1].hexSEED
                            self.result["mnemonic"] = x[1].mnemonic
            except:
                self.result[
                    "message"] = "There was a problem restoring your address. If you believe this is in error, please raise it with the QRL team."
                return helper.json_encode(self.result)

        # Invalid selection
        else:
            self.result[
                "message"] = "You must select either mnemonic or hexseed recovery options to restore an address!"
            return helper.json_encode(self.result)

        # If we got this far, it must have worked!
        self.result["status"] = "success"

        return helper.json_encode(self.result)


class memPoolSize(Resource):
    def __init__(self, chain):
        Resource.__init__(self)
        self.chain = chain

    isLeaf = True

    def render_GET(self, request):
        return str(len(self.chain.transaction_pool))


class syncStatus(Resource):
    def __init__(self, p2pFactory):
        Resource.__init__(self)
        self.p2pFactory = p2pFactory

    isLeaf = True

    def render_GET(self, request):
        return str(self.p2pFactory.nodeState.state)


class sendQuanta(Resource):
    def __init__(self, chain, state, p2pFactory):
        Resource.__init__(self)
        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.output = {}
        self.txnResult = {}

    isLeaf = True

    def render_POST(self, request):
        req = request.content.read()
        jsQ = json.loads(req)

        return self.send_tx(jsQ["from"], jsQ["to"], jsQ["amount"])

    # TODO
    # Bit of duplicated code here - couldn't get it to work directly.
    # Will follow up with cyyber
    def send_tx(self, wallet_from, wallet_to, send_amount):
        self.txnResult = {
            'status': 'fail',
            'message': '',
            'txnhash': '',
            'from': wallet_from,
            'to': wallet_to,
            'amount': send_amount
        }

        # Check if local wallet number is higher than the number of local wallets that are saved
        if int(wallet_from) > len(self.chain.wallet.list_addresses()) - 1:
            self.txnResult[
                "message"] = "Invalid sending address. Try a valid number from your wallet - type wallet for details."
            return helper.json_encode(self.txnResult)

        # if wallet_to is not a local wallet, and wallet_to is not prepended by Q and
        if len(wallet_to) > 1 and wallet_to[0] != 'Q' and self.state.state_hrs(wallet_to) != False:
            pass
        elif wallet_to[0] == 'Q':
            pass
        else:
            try:
                int(wallet_to)
            except:
                self.txnResult["message"] = "Invalid receiving address - addresses must start with Q."
                return helper.json_encode(self.txnResult)

            if int(wallet_to) > len(self.chain.wallet.list_addresses()) - 1:
                self.txnResult["message"] = "Invalid receiving address - addresses must start with Q."
                return helper.json_encode(self.txnResult)

            wallet_to = int(wallet_to)

        # Check to see if sending amount > amount owned (and reject if so)
        # This is hard to interpret. Break it up?
        balance = self.state.state_balance(self.chain.my[int(wallet_from)][0])
        try:
            float(send_amount)
        except:
            self.txnResult[
                "message"] = "Invalid amount type. Type a number (less than or equal to the balance of the sending address)"
            return helper.json_encode(self.txnResult)

        amount = decimal.Decimal(decimal.Decimal(send_amount) * 100000000).quantize(decimal.Decimal('1'),
                                                                                    rounding=decimal.ROUND_HALF_UP)

        if balance < amount:
            self.txnResult[
                "message"] = "Invalid amount to send. Type a number less than or equal to the balance of the sending address"
            return helper.json_encode(self.txnResult)

        # Stop user from sending less than their entire balance if they've only
        # got one signature remaining.
        sigsremaining = self.chain.wallet.get_num_signatures(self.chain.my[int(wallet_from)][0])
        if sigsremaining is 1:
            if amount < balance:
                self.txnResult[
                    "message"] = "Stop! You only have one signing signature remaining. You should send your entire balance or the remainder will be lost!"
                return helper.json_encode(self.txnResult)

        tx = self.chain.create_my_tx(txfrom=int(wallet_from), txto=wallet_to, amount=amount)

        if tx is False:
            self.txnResult["message"] = "Failed to Create txn"
            return helper.json_encode(self.txnResult)

        if tx.validate_tx():
            if not tx.state_validate_tx(state=self.state, transaction_pool=self.chain.transaction_pool):
                self.txnResult["message"] = "OTS key reused"
                return helper.json_encode(self.txnResult)
        else:
            self.txnResult["message"] = "TXN failed at validate_tx"
            return helper.json_encode(self.txnResult)

        # send the transaction to peers (ie send it to the network - we are done)
        self.p2pFactory.send_tx_to_peers(tx)

        print('>>> TXN Hash: ' + str(tx.txhash) + ', From: ' + str(tx.txfrom) + ' To: ' + str(tx.txto) + ' For: ' + str(
            tx.amount / 100000000.000000000) + '\r\n' + '>>>created and sent into p2p network')

        self.txnResult["status"] = "success"
        self.txnResult["txnhash"] = str(tx.txhash)
        self.txnResult["from"] = str(tx.txfrom)
        self.txnResult["to"] = str(tx.txto)
        self.txnResult["amount"] = str(tx.amount / 100000000.000000000)

        return helper.json_encode(self.txnResult)
