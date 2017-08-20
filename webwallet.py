# QRL Web Wallet
# localhost:8888/

__author__ = 'scottdonaldau'

from twisted.web.server import Site
from twisted.web.static import File
from twisted.web.resource import Resource
from twisted.internet import reactor, endpoints
from StringIO import StringIO
import decimal
import configuration as c
import helper
import time
import json
import os
import apiprotocol
import walletprotocol
import wallet


class WebWallet:
    def __init__(self, chain, state, p2pFactory):

        # Get working directory
        cwd = os.getcwd()

        self.cwd = cwd
        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.stuff = "QRL node connection established."
        self.wallet = wallet.Wallet(self.chain, self.state)

        # Start local web server and define routes
        resource = File(self.cwd + '/web-wallet')
        resource.putChild("webwallet-addresses", showAddresses(self.wallet))
        resource.putChild("webwallet-create-new-address", newAddress(self.wallet))
        resource.putChild("webwallet-send", sendQuanta(self.chain, self.state, self.p2pFactory))

        factory = Site(resource)
        endpoint = endpoints.TCP4ServerEndpoint(reactor, 8888, interface='127.0.0.1')
        endpoint.listen(factory)


class showAddresses(Resource):
    def __init__(self, Wallet):
        self.wallet = Wallet

    isLeaf = True
    def render_GET(self, request):
        return helper.json_encode(self.wallet.list_addresses())


class newAddress(Resource):
    def __init__(self, Wallet):
        self.wallet = Wallet

    isLeaf = True
    def render_GET(self, request):
        return self.wallet.savenewaddress(signatures=4096, type='XMSS')


class sendQuanta(Resource):
    def __init__(self, chain, state, p2pFactory):
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
            self.txnResult["message"] = "Invalid sending address. Try a valid number from your wallet - type wallet for details."
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
            self.txnResult["message"] = "Invalid amount type. Type a number (less than or equal to the balance of the sending address)"
            return helper.json_encode(self.txnResult)

        amount = decimal.Decimal(decimal.Decimal(send_amount) * 100000000).quantize(decimal.Decimal('1'), rounding=decimal.ROUND_HALF_UP)

        if balance < amount:
            self.txnResult["message"] = "Invalid amount to send. Type a number less than or equal to the balance of the sending address"
            return helper.json_encode(self.txnResult)

        # Stop user from sending less than their entire balance if they've only
        # got one signature remaining.
        sigsremaining = self.chain.wallet.get_num_signatures(self.chain.my[int(wallet_from)][0])
        if sigsremaining is 1:
            if amount < balance:
                self.txnResult["message"] = "Stop! You only have one signing signature remaining. You should send your entire balance or the remainder will be lost!"
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




