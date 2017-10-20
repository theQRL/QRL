# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
# QRL Web Wallet
# localhost:8888/
import json
import os

from pyqrllib.pyqrllib import hstr2bin, mnemonic2bin
from twisted.internet import reactor, endpoints
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web.static import File

from qrl.crypto.mnemonic import validate_mnemonic


def hexseed_to_seed(hex_seed):
    if len(hex_seed) != 96:
        return False
    return hstr2bin(hex_seed)


class WebWallet:
    def __init__(self, chain, state, p2pFactory, qrlnode):
        package_directory = os.path.dirname(os.path.abspath(__file__))

        self.chain = chain
        self.state = state
        self.p2pFactory = p2pFactory
        self.qrlnode = qrlnode

        # Start local web server and define routes
        resource = File(os.path.join(package_directory, 'web-wallet'))
        resource.putChild(b"webwallet-addresses", showAddresses(self.chain))
        resource.putChild(b"webwallet-create-new-address", newAddress(self.chain))
        resource.putChild(b"webwallet-send", sendQuanta(self.chain, self.state, self.qrlnode))
        resource.putChild(b"webwallet-mempool", memPoolSize(self.chain))
        resource.putChild(b"webwallet-sync", syncStatus(self.p2pFactory))
        resource.putChild(b"webwallet-recover", recoverAddress(self.chain))

        factory = Site(resource)
        endpoint = endpoints.TCP4ServerEndpoint(reactor, 8888, interface='127.0.0.1')
        endpoint.listen(factory)


class showAddresses(Resource):
    def __init__(self, chain):
        Resource.__init__(self)
        self.chain = chain

    isLeaf = True

    def render_GET(self, request):
        tmp = self.chain.wallet.list_addresses(self.chain.state, self.chain.transaction_pool)
        return bytes(json.dumps(tmp), 'utf-8')


class newAddress(Resource):
    def __init__(self, chain):
        Resource.__init__(self)
        self.chain = chain

    isLeaf = True

    def render_GET(self, request):
        addr = self.chain.wallet.get_new_address()
        self.chain.wallet.append_wallet(addr)


class recoverAddress(Resource):
    def __init__(self, Chain):
        Resource.__init__(self)
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
                return bytes(json.dumps(self.result), 'utf-8')

            # FIXME: Validation should not be here, it should be part of mnemonic
            mnemonicphrase = jsQ["words"]

            if not validate_mnemonic(mnemonicphrase):
                self.result["message"] = "Invalid mnemonic phrase! It must contain exactly 32 valid words"
                return bytes(json.dumps(self.result), 'utf-8')

            # Try to recover
            try:
                addr = self.chain.wallet.get_new_address(seed=mnemonic2bin(mnemonicphrase))
                self.chain.wallet.append_wallet(addr)
                
                # Find hex/mnemonic for recovered wallet
                self.result["recoveredAddress"] = addr[1].get_address()
                self.result["hexseed"] = addr[1].get_hexseed()
                self.result["mnemonic"] = addr[1].get_mnemonic()

            except:
                self.result[
                    "message"] = "There was a problem restoring your address. " \
                                 "If you believe this is in error, please raise it with the QRL team."

                return bytes(json.dumps(self.result), 'utf-8')

        # Recover address from hexseed
        elif jsQ["type"] == "hexseed":
            if not jsQ["hexseed"] or not hexseed_to_seed(jsQ["hexseed"]):
                self.result["message"] = "Invalid Hex Seed!"
                return bytes(json.dumps(self.result), 'utf-8')

            # Try to recover
            try:
                addr = self.chain.wallet.get_new_address(seed=hexseed_to_seed(jsQ["hexseed"]))
                self.chain.wallet.append_wallet(addr)
                
                # Find hex/mnemonic for recovered wallet
                self.result["recoveredAddress"] = addr[1].get_address()
                self.result["hexseed"] = addr[1].get_hexseed()
                self.result["mnemonic"] = addr[1].get_mnemonic()

            except:
                self.result[
                    "message"] = "There was a problem restoring your address. If you believe this is in error, please raise it with the QRL team."
                return bytes(json.dumps(self.result), 'utf-8')

        # Invalid selection
        else:
            self.result[
                "message"] = "You must select either mnemonic or hexseed recovery options to restore an address!"
            return bytes(json.dumps(self.result), 'utf-8')

        # If we got this far, it must have worked!
        self.result["status"] = "success"

        return bytes(json.dumps(self.result), 'utf-8')


class memPoolSize(Resource):
    def __init__(self, chain):
        Resource.__init__(self)
        self.chain = chain

    isLeaf = True

    def render_GET(self, request):
        return bytes(str(len(self.chain.transaction_pool)), 'utf-8')


class syncStatus(Resource):
    def __init__(self, p2pFactory):
        Resource.__init__(self)
        self.p2pFactory = p2pFactory

    isLeaf = True

    def render_GET(self, request):
        return bytes(str(self.p2pFactory.nodeState.state), 'utf-8')


class sendQuanta(Resource):
    def __init__(self, chain, state, qrlnode):
        Resource.__init__(self)
        self.chain = chain
        self.state = state
        self.qrlnode = qrlnode
        self.output = {}
        self.txnResult = {}

    isLeaf = True

    def render_POST(self, request):
        req = request.content.read()
        jsQ = json.loads(req)

        return self.send_tx(jsQ["from"], jsQ["to"], jsQ["amount"])

    # FIXME: Missing fee. It wont get fixed as the webwallet will get removed
    def send_tx(self, wallet_from, wallet_to, amount_arg):
        fee_arg = 0  # FIXME: Fee argument is missing here, the class will be removed. No plans for fixing this

        self.txnResult = {
            'status': 'fail',
            'message': '',
            'txnhash': '',
            'from': wallet_from,
            'to': wallet_to,
            'amount': amount_arg
        }

        qrlnode = self.qrlnode

        ########################
        ########################

        try:
            wallet_from = qrlnode.get_wallet_absolute(wallet_from.encode())
            wallet_to = qrlnode.get_wallet_absolute(wallet_to.encode())
            amount = qrlnode.get_dec_amount(amount_arg)
            fee = qrlnode.get_dec_amount(fee_arg)

            tx = qrlnode.transfer_coins(wallet_from, wallet_to, amount, fee)

        except Exception as e:
            self.txnResult["message"] = str(e)
            return bytes(json.dumps(self.txnResult), 'utf-8')

        ################################
        ################################

        self.txnResult["status"] = "success"
        self.txnResult["txnhash"] = str(tx.txhash)
        self.txnResult["from"] = str(tx.txfrom)
        self.txnResult["to"] = str(tx.txto)
        # FIXME: Magic number? Unify
        self.txnResult["amount"] = str(tx.amount / 100000000.000000000)
        return bytes(json.dumps(self.txnResult), 'utf-8')
