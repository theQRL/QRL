import statistics
import json
import helper
import copy
import decimal
import time
from twisted.internet.protocol import ServerFactory, Protocol


# factories and protocols..
class ApiProtocol(Protocol):
    def __init__(self):
        self.api_list = [
            'block_data', 'stats', 'ip_geotag', 'exp_win', 'txhash', 'address',
            'empty', 'last_tx', 'stake_reveal_ones', 'last_block', 'richlist',
            'ping', 'stake_commits', 'stake_reveals', 'stake_list', 'stakers',
            'next_stakers', 'latency'
        ]

    def parse_cmd(self, data):

        data = data.split()  # typical request will be: "GET /api/{command}/{parameter} HTTP/1.1"

        if len(data) == 0:
            return

        if data[0] != 'GET' and data[0] != 'OPTIONS':
            return False

        if data[0] == 'OPTIONS':
            http_header_OPTIONS = ("HTTP/1.1 200 OK\r\n"
                                   "Access-Control-Allow-Origin: *\r\n"
                                   "Access-Control-Allow-Methods: GET\r\n"
                                   "Access-Control-Allow-Headers: x-prototype-version,x-requested-with\r\n"
                                   "Content-Length: 0\r\n"
                                   "Access-Control-Max-Age: 2520\r\n"
                                   "\r\n")
            self.transport.write(http_header_OPTIONS)
            return

        data = data[1][1:].split('/')

        if data[0].lower() != 'api':
            return False

        if len(data) == 1:
            data.append('')

        if data[1] == '':
            data[1] = 'empty'

        if data[1].lower() not in self.api_list:  # supported {command} in api_list
            error = {'status': 'error', 'error': 'supported method not supplied', 'parameter': data[1]}
            self.transport.write(helper.json_print_telnet(error))
            return False

        #my_cls = ApiProtocol()  # call the command from api_list directly
        api_call = getattr(self, data[1].lower())

        if len(data) < 3:
            json_txt = api_call()
        # self.transport.write(api_call())
        else:
            json_txt = api_call(data[2])
        # self.transport.write(api_call(data[2]))

        http_header_GET = ("HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %s\r\n"
                           "Access-Control-Allow-Headers: x-prototype-version,x-requested-with\r\n"
                           "Access-Control-Max-Age: 2520\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Methods: GET\r\n"
                           "\r\n") % (str(len(json_txt)))

        self.transport.write(http_header_GET + json_txt)
        return

    def exp_win(self, data=None):
        printL(('<<< API expected winner call'))
        return self.factory.chain.exp_win(data)

    def ping(self, data=None):
        printL(('<<< API network latency ping call'))
        self.factory.ping_peers()  # triggers ping for all connected peers at timestamp now. after pong response list is collated. previous list is delivered.
        pings = {}
        pings['status'] = 'ok'
        pings['peers'] = {}
        pings['peers'] = self.factory.chain.ping_list
        return helper.json_print_telnet(pings)

    def stakers(self, data=None):
        printL(('<<< API stakers call'))
        return self.factory.chain.stakers(data)

    def next_stakers(self, data=None):
        printL(('<<< API next_stakers call'))
        return self.factory.chain.next_stakers(data)

    def stake_commits(self, data=None):
        printL(('<<< API stake_commits call'))
        return self.factory.chain.stake_commits(data)

    def stake_reveals(self, data=None):
        printL(('<<< API stake_reveals call'))
        return self.factory.chain.stake_reveals(data)

    def stake_reveal_ones(self, data=None):
        printL(('<<< API stake_reveal_ones'))
        return self.factory.chain.stake_reveal_ones(data)

    def richlist(self, data=None):
        printL(('<<< API richlist call'))
        return self.factory.chain.richlist(data)

    def last_block(self, data=None):
        printL(('<<< API last_block call'))
        return self.factory.chain.last_block(data)

    def last_tx(self, data=None):
        printL(('<<< API last_tx call'))
        return self.factory.chain.last_tx(data)

    def ip_geotag(self, data=None):
        printL(('<<< API ip_geotag call'))
        self.factory.ip_geotag_peers()
        return self.factory.chain.ip_geotag(data)

    def empty(self, data=None):
        error = {
            'status': 'error',
            'error': 'no method supplied',
            'methods available':
                'block_data, stats, txhash, address, last_tx, \
                last_block, richlist, ping, stake_commits, stake_reveals, stakers, \
                next_stakers'
        }
        return helper.json_print_telnet(error)

    def block_data(self, data=None):  # if no data = last block ([-1])			#change this to add error..
        error = {
            'status': 'error',
            'error': 'block not found',
            'method': 'block_data',
            'parameter': data
        }
        printL(('<<< API block data call', data))
        if not data:
            data = self.factory.chain.m_get_last_block()
            data1 = copy.deepcopy(data)
            data1.status = 'ok'
            return helper.json_print_telnet(data1)
        try:
            int(data)  # is the data actually a number?
        except:
            return helper.json_print_telnet(error)
        js_bk = self.factory.chain.m_get_block(int(data))
        if js_bk == False:
            return helper.json_print_telnet(error)
        else:
            js_bk1 = copy.deepcopy(js_bk)
            js_bk1.status = 'ok'
            js_bk1.blockheader.block_reward = js_bk1.blockheader.block_reward / 100000000.000000000
            return helper.json_print_telnet(js_bk1)

    def stats(self, data=None):
        printL(('<<< API stats call'))

        # calculate staked/emission %
        b = 0
        for s in self.factory.state.stake_list_get():
            b += self.factory.state.state_balance(s[0])
        staked = decimal.Decimal((b / 100000000.000000000) / (
        self.factory.state.db.total_coin_supply() / 100000000.000000000) * 100).quantize(
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

        net_stats = {'status': 'ok', 'version': self.factory.chain.version_number,
                     'block_reward': self.factory.chain.m_blockchain[-1].blockheader.block_reward / 100000000.00000000,
                     'stake_validators': len(self.factory.chain.m_blockchain[-1].blockheader.reveal_list),
                     'epoch': self.factory.chain.m_blockchain[-1].blockheader.epoch,
                     'staked_percentage_emission': staked, 'network': 'qrl testnet',
                     'network_uptime': time.time() - self.factory.chain.m_blockchain[1].blockheader.timestamp,
                     'block_time': z / len(t),
                     'block_time_variance': max(t) - min(t), 'blockheight': self.factory.chain.m_blockheight(),
                     'nodes': len(self.factory.peers) + 1,
                     'emission': self.factory.state.db.total_coin_supply() / 100000000.000000000,
                     'unmined': 21000000 - self.factory.state.db.total_coin_supply() / 100000000.000000000}
        return helper.json_print_telnet(net_stats)

    def txhash(self, data=None):
        printL(('<<< API tx/hash call', data))
        return self.factory.chain.search_txhash(data)

    def address(self, data=None):
        printL(('<<< API address call', data))
        return self.factory.chain.search_address(data)

    def dataReceived(self, data=None):
        self.parse_cmd(data)
        self.transport.loseConnection()

    def connectionMade(self):
        self.factory.connections += 1

    def connectionLost(self, reason):
        self.factory.connections -= 1

    def latency(self, type=None):
        output = {}
        if type and type.lower() in ['mean', 'median', 'last']:
            for block_num in self.factory.chain.stake_validator_latency.keys():
                output[block_num] = {}
                for stake in self.factory.chain.stake_validator_latency[block_num].keys():
                    time_list = self.factory.chain.stake_validator_latency[block_num][stake]
                    print time_list
                    output[block_num][stake] = {}
                    if 'r2_time_diff' in time_list:
                        return
                    if type.lower() == 'mean':
                        output[block_num][stake]['r1_time_diff'] = statistics.mean(
                            time_list['r1_time_diff'])
                        output[block_num][stake]['r2_time_diff'] = statistics.mean(
                            time_list['r2_time_diff'])
                    elif type.lower() == 'last':
                        output[block_num][stake]['r1_time_diff'] = time_list['r1_time_diff'][-1]
                        output[block_num][stake]['r2_time_diff'] = time_list['r2_time_diff'][-1]
                    elif type.lower() == 'median':
                        output[block_num][stake]['r1_time_diff'] = statistics.median(
                            time_list['r1_time_diff'])
                        output[block_num][stake]['r2_time_diff'] = statistics.median(
                            time_list['r2_time_diff'])
        else:
            output = self.factory.chain.stake_validator_latency
        output = json.dumps(output)
        return output


class ApiFactory(ServerFactory):
    def __init__(self, chain, state, peers):
        self.protocol = ApiProtocol
        self.connections = 0
        self.api = 1
        self.chain = chain
        self.state = state
        self.peers = peers

    '''
    def buildProtocol(self, addr):
        self.protocol = ApiProtocol()
        self.protocol.factory = self
        return self.protocol
    '''