# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
import decimal
import json
import time
from operator import itemgetter

import statistics
from twisted.internet.protocol import Protocol, connectionDone

from pyqrllib.pyqrllib import bin2hstr
from qrl.core import config, logger
from qrl.core.helper import json_print_telnet
from qrl.core.Transaction_subtypes import TX_SUBTYPE_TX, TX_SUBTYPE_COINBASE, TX_SUBTYPE_STAKE
from qrl.core.Transaction import SimpleTransaction, CoinBase, Transaction


class ApiProtocol(Protocol):
    def __init__(self):
        self.api_list = [
            'block_data',
            'stats',
            'ip_geotag',
            'txhash',
            'address',
            'empty',
            'last_tx',
            'last_unconfirmed_tx',
            'last_block',
            'richlist',
            'ping',
            'stakers',
            'next_stakers',
            'latency',
            'balance'
        ]

    def parse_cmd(self, data):

        data = data.split()  # typical request will be: "GET /api/{command}/{parameter} HTTP/1.1"

        if len(data) == 0:
            return

        if data[0] != b'GET' and data[0] != b'OPTIONS':
            return False

        if data[0] == b'OPTIONS':
            http_header_OPTIONS = ("HTTP/1.1 200 OK\r\n"
                                   "Access-Control-Allow-Origin: *\r\n"
                                   "Access-Control-Allow-Methods: GET\r\n"
                                   "Access-Control-Allow-Headers: x-prototype-version,x-requested-with\r\n"
                                   "Content-Length: 0\r\n"
                                   "Access-Control-Max-Age: 2520\r\n"
                                   "\r\n")
            self.transport.write(http_header_OPTIONS)
            return

        data = data[1].decode('ascii')[1:].split('/')

        if data[0].lower() != 'api':
            return False

        if len(data) == 1:
            data.append('')

        if data[1] == '':
            data[1] = 'empty'

        if data[1].lower() not in self.api_list:  # supported {command} in api_list
            error = {'status': 'error', 'error': 'supported method not supplied', 'parameter': data[1]}
            self.transport.write(json_print_telnet(error))
            return False

        api_call = getattr(self, data[1].lower())

        if len(data) < 3:
            json_txt = api_call()
        else:
            json_txt = api_call(data[2])

        http_header_GET = ("HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %s\r\n"
                           "Access-Control-Allow-Headers: x-prototype-version,x-requested-with\r\n"
                           "Access-Control-Max-Age: 2520\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Methods: GET\r\n"
                           "\r\n") % (str(len(json_txt)))

        self.transport.write(bytes(http_header_GET + json_txt, 'utf-8'))
        return

    def ping(self, data=None):
        logger.info('<<< API network latency ping call')
        self.factory.pos.p2pFactory.ping_peers()  # triggers ping for all connected peers at timestamp now. after pong response list is collated. previous list is delivered.

        pings = {'status': 'ok',
                 'peers': self.factory.chain.ping_list}

        return json_print_telnet(pings)

    def stakers(self, data=None):
        logger.info('<<< API stakers call')

        stakers = {'status': 'ok',
                   'stake_list': []}

        for staker in self.factory.state.stake_validators_list.sv_list:
            sv = self.factory.state.stake_validators_list.sv_list[staker]
            tmp_stakers = {'address': sv.stake_validator,
                           'balance': self.factory.format_qrlamount(sv.balance),
                           'hash_terminator': [],
                           'nonce': sv.nonce}

            for i in range(len(sv.hashchain_terminators)):
                tmp_stakers['hash_terminator'].append(bin2hstr(sv.hashchain_terminators[i]))

            stakers['stake_list'].append(tmp_stakers)

        return json_print_telnet(stakers)

    def next_stakers(self, data=None):
        logger.info('<<< API next_stakers call')

        next_stakers = {'status': 'ok',
                        'stake_list': []}

        for staker in self.factory.state.stake_validators_list.next_sv_list:
            sv = self.factory.state.stake_validators_list.next_sv_list[staker]
            tmp_stakers = {'address': sv.stake_validator,
                           'balance': self.factory.format_qrlamount(sv.balance),
                           'hash_terminator': [],
                           'nonce': sv.nonce}


            for i in range(len(sv.hashchain_terminators)):
                tmp_stakers['hash_terminator'].append(bin2hstr(sv.hashchain_terminators[i]))

            next_stakers['stake_list'].append(tmp_stakers)

        return json_print_telnet(next_stakers)

    def richlist(self, data=None):
        """
        only feasible while chain is small..
        :param data:
        :return:
        """
        logger.info('<<< API richlist call')

        if not data:
            data = 5

        error = {'status': 'error',
                 'error': 'invalid argument',
                 'method': 'richlist',
                 'parameter': data}

        try:
            n = int(data)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        if not self.factory.state.state_uptodate(self.factory.chain.m_blockheight()):
            return json_print_telnet({'status': 'error',
                                      'error': 'leveldb failed',
                                      'method': 'richlist'})

        addr = self.factory.state.return_all_addresses()
        richlist = sorted(addr, key=itemgetter(1), reverse=True)

        rl = {'richlist': {}}

        if len(richlist) < n:
            n = len(richlist)

        for rich in richlist[:n]:
            rl['richlist'][richlist.index(rich) + 1] = {}
            rl['richlist'][richlist.index(rich) + 1]['address'] = rich[0].decode()
            rl['richlist'][richlist.index(rich) + 1]['balance'] = self.factory.format_qrlamount(rich[1])

        rl['status'] = 'ok'

        return json_print_telnet(rl)

    def last_block(self, data=None):
        logger.info('<<< API last_block call')

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_block', 'parameter': data}

        if not data:
            data = 1

        try:
            n = int(data)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        lb = []
        beginning = self.factory.chain.height() - n
        for blocknum in range(self.factory.chain.height(), beginning - 1, -1):
            block = self.factory.chain.m_get_block(blocknum)
            lb.append(block)

        last_blocks = {'blocks': []}
        i = 0
        for block in lb[1:]:
            i += 1
            tmp_block = {'blocknumber': block.blockheader.blocknumber,
                         'block_reward': self.factory.format_qrlamount(block.blockheader.block_reward),
                         'blockhash': bin2hstr(block.blockheader.prev_blockheaderhash),
                         'timestamp': block.blockheader.timestamp,
                         'block_interval': lb[i - 1].blockheader.timestamp - block.blockheader.timestamp,
                         'number_transactions': len(block.transactions)}

            last_blocks['blocks'].append(tmp_block)

        last_blocks['status'] = 'ok'

        return json_print_telnet(last_blocks)

    def last_unconfirmed_tx(self, data=None):
        logger.info('<<< API last_unconfirmed_tx call')

        addr = {'transactions': []}
        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': data}

        if not data:
            data = 1
        try:
            n = int(data)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        tx_num = len(self.factory.chain.transaction_pool)
        while tx_num > 0:
            tx_num -= 1
            tx = self.factory.chain.transaction_pool[tx_num]
            if tx.subtype != TX_SUBTYPE_TX:
                continue
            tmp_txn = {'txhash': bin2hstr(tx.txhash),
                       'block': 'unconfirmed',
                       'timestamp': 'unconfirmed',
                       'amount': self.factory.format_qrlamount(tx.amount),
                       'type': tx.subtype}

            tmp_txn['type'] = Transaction.tx_id_to_name(tmp_txn['type'])
            addr['transactions'].append(tmp_txn)

        addr['status'] = 'ok'
        return json_print_telnet(addr)

    def last_tx(self, data=None):
        logger.info('<<< API last_tx call')

        if not data:
            data = 1

        addr = {'transactions': []}

        error = {'status': 'error', 'error': 'invalid argument', 'method': 'last_tx', 'parameter': data}

        try:
            n = int(data)
        except:
            return json_print_telnet(error)

        if n <= 0 or n > 20:
            return json_print_telnet(error)

        try:
            last_txn = self.factory.state.db.get('last_txn')
        except Exception:
            error['error'] = 'txnhash not found'
            return json_print_telnet(error)

        n = min(len(last_txn), n)
        while n > 0:
            n -= 1
            tx_meta = last_txn[n]
            tx = SimpleTransaction().json_to_transaction(tx_meta[0])
            tmp_txn = {'txhash': bin2hstr(tx.txhash),
                       'block': tx_meta[1],
                       'timestamp': tx_meta[2],
                       'amount': self.factory.format_qrlamount(tx.amount),
                       'type': tx.subtype}

            addr['transactions'].append(tmp_txn)
            addr['status'] = 'ok'

        return json_print_telnet(addr)

    def ip_geotag(self, data=None):
        logger.info('<<< API ip_geotag call')
        self.factory.pos.p2pFactory.ip_geotag_peers()
        ip = {'status': 'ok',
              'ip_geotag': self.factory.chain.ip_list}

        x = 0
        for i in self.factory.chain.ip_list:
            ip['ip_geotag'][x] = i
            x += 1

        return json_print_telnet(ip)

    def empty(self, data=None):
        error = {
            'status': 'error',
            'error': 'no method supplied',
            'methods available': self.api_list
        }
        return json_print_telnet(error)

    def reformat_block(self, block):
        block.blockheader.block_reward = self.factory.format_qrlamount(block.blockheader.block_reward)
        block.blockheader.fee_reward = self._factory.format_qrlamount(block.blockheader.fee_reward)
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
            txn.amount = self.factory.format_qrlamount(txn.amount)
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

    def block_data(self, data=None):  # if no data = last block ([-1])			#change this to add error..
        error = {
            'status': 'error',
            'error': 'block not found',
            'method': 'block_data',
            'parameter': data
        }
        logger.info('<<< API block data call %s', data)
        if not data:
            data = self.factory.chain.height()

        try:
            int(data)  # is the data actually a number?
        except:
            return json_print_telnet(error)

        js_bk = self.factory.chain.m_get_block(int(data))

        if not js_bk:
            return json_print_telnet(error)
        else:
            js_bk1 = copy.deepcopy(js_bk)
            js_bk1.number_transactions = len(js_bk1.transactions)
            js_bk1.status = 'ok'
            self.reformat_block(js_bk1)

            return json_print_telnet(js_bk1)

    def stats(self, data=None):
        logger.info('<<< API stats call')

        # calculate staked/emission %
        b = 0
        for staker in self.factory.state.stake_validators_list.sv_list:
            b += self.factory.state.state_balance(staker)
        # FIXME: Magic number? Unify
        staked = decimal.Decimal((b / 100000000.000000000) / (
        self.factory.state.total_coin_supply() / 100000000.000000000) * 100).quantize(
            decimal.Decimal('1.00'))  # /100000000.000000000)
        staked = float(str(staked))

        # calculate average blocktime over last 100 blocks..
        z = 0
        t = []

        last_n_block = 100

        last_block = self.factory.chain.m_blockchain[-1]
        for _ in range(last_n_block):
            if last_block.blockheader.blocknumber <= 0:
                break
            prev_block = self.factory.chain.m_get_block(last_block.blockheader.blocknumber - 1)
            x = last_block.blockheader.timestamp - prev_block.blockheader.timestamp
            last_block = prev_block
            t.append(x)
            z += x

        block_one = self.factory.chain.m_get_block(1)
        network_uptime = 0
        if block_one:
            network_uptime = time.time() - block_one.blockheader.timestamp

        block_time = 0
        block_time_variance = 0
        if len(t) > 0:
            block_time = z / len(t)
            block_time_variance = max(t) - min(t)   # FIXME: This is not the variance!

        net_stats = {'status': 'ok', 'version': self.factory.chain.version_number,
                     'block_reward': self.factory.format_qrlamount(self.factory.chain.m_blockchain[-1].blockheader.block_reward),
                     'stake_validators': len(self.factory.chain.state.stake_validators_list.sv_list),
                     'epoch': self.factory.chain.m_blockchain[-1].blockheader.epoch,
                     'staked_percentage_emission': staked, 'network': 'qrl testnet',
                     'network_uptime': network_uptime,
                     'block_time': block_time,
                     'block_time_variance': block_time_variance,
                     'blockheight': self.factory.chain.m_blockheight(),
                     'nodes': len(self.factory.peers) + 1,
                     # FIXME: Magic number? Unify
                     'emission': self._format_qrlamount(self.factory.state.total_coin_supply()),
                     'unmined': config.dev.total_coin_supply - self.factory.state.total_coin_supply() / 100000000.000000000}

        return json_print_telnet(net_stats)

    def txhash(self, data=None):
        logger.info('<<< API tx/hash call %s', data)
        return self.search_txhash(data)

    def balance(self, data=None):
        # NOTE: GRPC ALTERNATIVE READY
        logger.info('<<< API balance call %s', data)

        address = data

        addr = {}

        # FIXME: breaking encapsulation and accessing DB/cache directly from API
        if not self.factory.state.state_address_used(address):
            addr['status'] = 'error'
            addr['error'] = 'Address not found'
            addr['parameter'] = address
            return json_print_telnet(addr)

        # FIXME: breaking encapsulation and accessing DB/cache directly from API
        nonce, balance, _ = self.factory.state.state_get_address(address)
        addr['state'] = {}
        addr['state']['address'] = address
        addr['state']['balance'] = self.factory.format_qrlamount(balance)
        addr['state']['nonce'] = nonce
        addr['state']['transactions'] = self.factory.state.state_get_txn_count(address)
        addr['status'] = 'ok'

        return json_print_telnet(addr)

    # used for port 80 api - produces JSON output reporting every transaction for an address, plus final balance..

    def address(self, data=None):
        logger.info('<<< API address call %s', data)
        return self._search_address(data)

    def dataReceived(self, data=None):
        self.parse_cmd(data)
        self.transport.loseConnection()

    def connectionMade(self):
        self.factory.connections += 1

    def connectionLost(self, reason=connectionDone):
        self.factory.connections -= 1
        logger.info("Connection lost: %s", reason)

    def latency(self, mtype=None):
        output = {}
        if mtype and mtype.lower() in ['mean', 'median', 'last']:
            for block_num in list(self.factory.chain.stake_validator_latency.keys()):
                output[block_num] = {}
                for stake in list(self.factory.chain.stake_validator_latency[block_num].keys()):
                    time_list = self.factory.chain.stake_validator_latency[block_num][stake]
                    logger.info(time_list)
                    output[block_num][stake] = {}
                    if 'r2_time_diff' in time_list:
                        return
                    if mtype.lower() == 'mean':
                        output[block_num][stake]['r1_time_diff'] = statistics.mean(
                            time_list['r1_time_diff'])
                        output[block_num][stake]['r2_time_diff'] = statistics.mean(
                            time_list['r2_time_diff'])
                    elif mtype.lower() == 'last':
                        output[block_num][stake]['r1_time_diff'] = time_list['r1_time_diff'][-1]
                        output[block_num][stake]['r2_time_diff'] = time_list['r2_time_diff'][-1]
                    elif mtype.lower() == 'median':
                        output[block_num][stake]['r1_time_diff'] = statistics.median(
                            time_list['r1_time_diff'])
                        output[block_num][stake]['r2_time_diff'] = statistics.median(
                            time_list['r2_time_diff'])
        else:
            output = self.factory.chain.stake_validator_latency
        output = json.dumps(output)
        return output

    ##########################

    def _format_qrlamount(self, balance):
        # FIXME: Magic number? Unify
        return format(float(balance / 100000000.00000000), '.8f').rstrip('.0')

    def _search_address(self, address):
        return self.factory.search_address(address)

    def search_txhash(self, txhash):  # txhash is unique due to nonce.
        return self.factory.search_txhash(txhash)
