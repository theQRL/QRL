# coding=utf-8
# QRL Web Wallet
# localhost:8888/
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import decimal
import json
import os

from twisted.internet import reactor, endpoints
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web.static import File

from qrl.core import helper
from qrl.core.wallet import Wallet
from qrl.crypto.hmac_drbg import hexseed_to_seed
from qrl.crypto.mnemonic import mnemonic_to_seed, validate_mnemonic
from qrl.crypto.xmss import XMSS

__author__ = 'scottdonaldau'


class WebWallet:
    def __init__(self, chain, state, p2pFactory):
        package_directory = os.path.dirname(os.path.abspath(__file__))

        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.wallet = Wallet()

        # Start local web server and define routes
        resource = File(os.path.join(package_directory, 'web-wallet'))
        resource.putChild("webwallet-addresses", showAddresses(self.chain))
        resource.putChild("webwallet-create-new-address", newAddress(self.wallet))
        resource.putChild("webwallet-send", sendQuanta(self.chain, self.state, self.p2pFactory))
        resource.putChild("webwallet-mempool", memPoolSize(self.chain))
        resource.putChild("webwallet-sync", syncStatus(self.p2pFactory))
        resource.putChild("webwallet-recover", recoverAddress(self.wallet, self.chain))

        factory = Site(resource)
        endpoint = endpoints.TCP4ServerEndpoint(reactor, 8888, interface='127.0.0.1')
        endpoint.listen(factory)


class showAddresses(Resource):
    def __init__(self, chain):
        Resource.__init__(self)
        self.chain = chain

    isLeaf = True

    def render_GET(self, request):
        return helper.json_encode(self.chain.wallet.list_addresses(self.chain.state, self.chain.transaction_pool))


class newAddress(Resource):
    def __init__(self, wallet):
        Resource.__init__(self)
        self.wallet = wallet

    isLeaf = True

    def render_GET(self, request):
        # FIXME: Parameterization spread in multiple places and in view/interfaces. Unify
        return self.wallet.savenewaddress(number_signatures=8000, addrtype='XMSS')


class recoverAddress(Resource):
    def __init__(self, wallet, Chain):
        Resource.__init__(self)
        self.wallet = wallet
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

            # FIXME: Validation should not be here, it should be part of mnemonic
            mnemonicphrase = jsQ["words"]

            if not validate_mnemonic(mnemonicphrase):
                self.result["message"] = "Invalid mnemonic phrase! It must contain exactly 32 valid words"
                return helper.json_encode(self.result)

            # Try to recover
            try:
                # FIXME: Parameterization spread in multiple places and in view/interfaces. Unify
                addr = self.chain.wallet.get_new_address(addrtype='XMSS', SEED=mnemonic_to_seed(mnemonicphrase))
                self.chain.wallet.append_wallet(addr)
                
                # Find hex/mnemonic for recovered wallet
                self.result["recoveredAddress"] = addr[1].get_address()
                self.result["hexseed"] = addr[1].get_hexseed()
                self.result["mnemonic"] = addr[1].get_mnemonic()

            except:
                self.result[
                    "message"] = "There was a problem restoring your address. " \
                                 "If you believe this is in error, please raise it with the QRL team."

                return helper.json_encode(self.result)

        # Recover address from hexseed
        elif jsQ["type"] == "hexseed":
            if not jsQ["hexseed"] or not hexseed_to_seed(jsQ["hexseed"]):
                self.result["message"] = "Invalid Hex Seed!"
                return helper.json_encode(self.result)

            # Try to recover
            try:
                # FIXME: Parameterization spread in multiple places and in view/interfaces. Unify
                addr = self.chain.wallet.get_new_address(addrtype='XMSS', SEED=hexseed_to_seed(jsQ["hexseed"]))
                self.chain.wallet.append_wallet(addr)
                
                # Find hex/mnemonic for recovered wallet
                self.result["recoveredAddress"] = addr[1].get_address()
                self.result["hexseed"] = addr[1].get_hexseed()
                self.result["mnemonic"] = addr[1].get_mnemonic()

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
        if int(wallet_from) > len(self.chain.wallet.list_addresses(self.chain.state, self.chain.transaction_pool)) - 1:
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

            if int(wallet_to) > len(self.chain.wallet.list_addresses(self.chain.state, self.chain.transaction_pool)) - 1:
                self.txnResult["message"] = "Invalid receiving address - addresses must start with Q."
                return helper.json_encode(self.txnResult)

            wallet_to = int(wallet_to)

        # Check to see if sending amount > amount owned (and reject if so)
        # This is hard to interpret. Break it up?
        balance = self.state.state_balance(self.chain.wallet.address_bundle[int(wallet_from)].address)
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
        sigsremaining = self.chain.wallet.get_num_signatures(self.chain.wallet.address_bundle[int(wallet_from)].address)
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
            block_chain_buffer = self.chain.block_chain_buffer
            tx_state = block_chain_buffer.get_stxn_state(blocknumber=block_chain_buffer.height(),
                                                         addr=tx.txfrom)
            if not tx.state_validate_tx(tx_state=tx_state,
                                        transaction_pool=self.chain.transaction_pool):
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
