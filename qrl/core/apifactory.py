# coding=utf-8
import copy
from pyqrllib.pyqrllib import bin2hstr
from twisted.internet.protocol import ServerFactory

from qrl.core import logger
from qrl.core.Transaction import Transaction
from qrl.core.Transaction_subtypes import TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE, TX_SUBTYPE_STAKE
from qrl.core.apiprotocol import ApiProtocol
from qrl.core.helper import json_print_telnet
from decimal import Decimal

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
        return format(float(balance / Decimal(100000000.00000000)), '.8f')

    #FIXME: Temporarily moving this here to keep thing running. Remove/refactor
    def search_address(self, address):
        addr = {'transactions': []}

        txnhash_added = set()

        # FIXME: breaking encapsulation and accessing DB/cache directly from API
        if not self.state.address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return json_print_telnet(addr)

        # FIXME: This is a duplicate of balance
        # FIXME: breaking encapsulation and accessing DB/cache directly from API
        nonce, balance, pubhash_list = self.state.get_address(address)
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
            tx = Transaction.from_json(txn_metadata[0])

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

    def reformat_block(self, block):
        block.blockheader.block_reward = self.format_qrlamount(block.blockheader.block_reward)
        block.blockheader.fee_reward = self.format_qrlamount(block.blockheader.fee_reward)
        block.blockheader.reveal_hash = bin2hstr(block.blockheader.reveal_hash)
        block.blockheader.vote_hash = bin2hstr(block.blockheader.vote_hash)
        block.blockheader.headerhash = bin2hstr(block.blockheader.headerhash)
        block.blockheader.tx_merkle_root = bin2hstr(block.blockheader.tx_merkle_root)
        block.blockheader.prev_blockheaderhash = bin2hstr(block.blockheader.prev_blockheaderhash)

        for txn in block.transactions:
            self.reformat_txn(txn)

        return block

    def reformat_txn(self, txn):
        if txn.subtype in (TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE):
            txn.amount = self.format_qrlamount(txn.amount)
        txn.txhash = bin2hstr(txn.txhash)
        txn.pubhash = bin2hstr(txn.pubhash)
        txn.signature = bin2hstr(txn.signature)
        txn.PK = bin2hstr(txn.PK)
        if txn.subtype == TX_SUBTYPE_STAKE:
            txn.slave_public_key = bin2hstr(txn.slave_public_key)
            if txn.first_hash:
                txn.first_hash = bin2hstr(txn.first_hash)
            for j in range(len(txn.hash)):
                txn.hash[j] = bin2hstr(txn.hash[j])

        txn.subtype = Transaction.tx_id_to_name(txn.subtype)
        return txn

    # FIXME: Temporarily moving this here to keep thing running. Remove/refactor
    def search_txhash(self, txhash):  # txhash is unique due to nonce.
        err = {'status': 'Error', 'error': 'txhash not found', 'method': 'txhash', 'parameter': txhash}
        for tx in self.chain.transaction_pool:
            if tx.txhash == txhash:
                logger.info('%s found in transaction pool..', txhash)
                tx_new = copy.deepcopy(tx)
                self.reformat_txn(tx_new)
                return json_print_telnet(tx_new)

        try:
            txn_metadata = self.chain.state.db.get(txhash)
        except:
            logger.info('%s does not exist in memory pool or local blockchain..', txhash)
            return json_print_telnet(err)

        tx = Transaction.from_json(txn_metadata[0])
        tx.blocknumber = txn_metadata[1]
        tx.confirmations = self.chain.height() - tx.blocknumber
        tx.timestamp = txn_metadata[2]

        tx_new = copy.deepcopy(tx)
        self.reformat_txn(tx_new)
        logger.info('%s found in block %s', txhash, str(txn_metadata[1]))
        tx_new.status = 'ok'
        return json_print_telnet(tx_new)
