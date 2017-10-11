# coding=utf-8
import copy
from jsonpickle import json
from pyqrllib._pyqrllib import bin2hstr
from twisted.internet.protocol import ServerFactory

from qrl.core import logger
from qrl.core.Transaction import Transaction, SimpleTransaction, CoinBase
from qrl.core.Transaction_subtypes import TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE
from qrl.core.apiprotocol import ApiProtocol
from qrl.core.helper import json_print_telnet


class ApiFactory(ServerFactory):
    def __init__(self, pos, chain, state, peers):
        self.protocol = ApiProtocol
        self.connections = 0
        self.api = 1
        self.pos = pos
        self.chain = chain
        self.state = state
        self.peers = peers

    def format_qrlamount(self, balance):
        return format(float(balance / 100000000.00000000), '.8f')

    #FIXME: Temporarily moving this here to keep thing running. Remove/refactor
    def search_address(self, address):
        addr = {'transactions': []}

        txnhash_added = set()

        # FIXME: breaking encapsulation and accessing DB/cache directly from API
        if not self.state.state_address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return json_print_telnet(addr)

        # FIXME: This is a duplicate of balance
        # FIXME: breaking encapsulation and accessing DB/cache directly from API
        nonce, balance, pubhash_list = self.state.state_get_address(address)
        addr['state'] = {}
        addr['state']['address'] = address
        addr['state']['balance'] = self.format_qrlamount(balance)
        addr['state']['nonce'] = nonce

        for s in self.state.stake_list_get():
            if address == s[0]:
                addr['stake'] = {}
                addr['stake']['selector'] = s[2]
                # pubhashes used could be put here..

        tmp_transactions = []
        for tx in self.chain.transaction_pool:
            if tx.subtype not in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
                continue
            if tx.txto == address or tx.txfrom == address:
                logger.info('%s found in transaction pool', address)

                tmp_txn = {'subtype': Transaction.tx_id_to_name(tx.subtype),
                           'txhash': bin2hstr(tx.txhash),
                           'block': 'unconfirmed',
                           'amount': self.format_qrlamount(tx.amount),
                           'nonce': tx.nonce,
                           'ots_key': tx.ots_key,
                           'txto': tx.txto,
                           'txfrom': tx.txfrom,
                           'timestamp': 'unconfirmed'}

                if tx.subtype == TX_SUBTYPE_TX:
                    tmp_txn['fee'] = self.format_qrlamount(tx.fee)

                tmp_transactions.append(tmp_txn)
                txnhash_added.add(tx.txhash)

        addr['transactions'] = tmp_transactions

        my_txn = []
        try:
            my_txn = self.state.db.get('txn_' + address)
        except:
            pass

        for txn_hash in my_txn:
            txn_metadata = self.state.db.get(txn_hash)
            dict_txn_metadata = json.loads(txn_metadata[0])
            if dict_txn_metadata['subtype'] == TX_SUBTYPE_TX:
                tx = SimpleTransaction().json_to_transaction(txn_metadata[0])
            elif dict_txn_metadata['subtype'] == TX_SUBTYPE_COINBASE:
                tx = CoinBase().json_to_transaction(txn_metadata[0])

            if (tx.txto == address or tx.txfrom == address) and tx.txhash not in txnhash_added:
                logger.info('%s found in block %s', address, str(txn_metadata[1]))

                tmp_txn = {'subtype': Transaction.tx_id_to_name(tx.subtype),
                           'txhash': bin2hstr(tx.txhash),
                           'block': txn_metadata[1],
                           'timestamp': txn_metadata[2],
                           'amount': self.format_qrlamount(tx.amount),
                           'nonce': tx.nonce,
                           'ots_key': tx.ots_key,
                           'txto': tx.txto,
                           'txfrom': tx.txfrom}

                if tx.subtype == TX_SUBTYPE_TX:
                    tmp_txn['fee'] = self.format_qrlamount(tx.fee)

                addr['transactions'].append(tmp_txn)
                txnhash_added.add(tx.txhash)

        if len(addr['transactions']) > 0:
            addr['state']['transactions'] = len(addr['transactions'])

        addr['status'] = 'ok'
        if addr == {'transactions': {}}:
            addr = {'status': 'error', 'error': 'address not found', 'method': 'address', 'parameter': address}

        return json_print_telnet(addr)

    # FIXME: Temporarily moving this here to keep thing running. Remove/refactor
    def search_txhash(self, txhash):  # txhash is unique due to nonce.
        err = {'status': 'Error', 'error': 'txhash not found', 'method': 'txhash', 'parameter': txhash}
        for tx in self.factory.chain.transaction_pool:
            if tx.txhash == txhash:
                logger.info('%s found in transaction pool..', txhash)
                tx_new = copy.deepcopy(tx)
                self.reformat_txn(tx_new)
                return json_print_telnet(tx_new)

        try:
            txn_metadata = self.factory.chain.state.db.get(txhash)
        except:
            logger.info('%s does not exist in memory pool or local blockchain..', txhash)
            return json_print_telnet(err)

        json_tx = json.loads(txn_metadata[0])
        tx = Transaction().from_txdict(json_tx)
        tx.blocknumber = txn_metadata[1]
        tx.confirmations = self.factory.chain.height() - tx.blocknumber
        tx.timestamp = txn_metadata[2]

        tx_new = copy.deepcopy(tx)
        self.reformat_txn(tx_new)
        logger.info('%s found in block %s', txhash, str(txn_metadata[1]))
        tx_new.status = 'ok'
        return json_print_telnet(tx_new)
