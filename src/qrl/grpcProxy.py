# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import argparse
import os
import simplejson as json
import grpc
from google.protobuf.json_format import MessageToJson
from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.crypto.xmss import XMSS
from qrl.core.txs.Transaction import Transaction
from qrl.core.txs.TransferTransaction import TransferTransaction
from pyqrllib.pyqrllib import hstr2bin, bin2hstr

from qrl.generated import qrl_pb2_grpc, qrl_pb2, qrlmining_pb2, qrlmining_pb2_grpc
from flask import Flask, Response, request
from jsonrpc.backend.flask import api

app = Flask(__name__)


def read_slaves(slaves_filename):
    with open(slaves_filename, 'r') as f:
        slave_data = json.load(f)
        slave_data[0] = bytes(hstr2bin(slave_data[0]))
        return slave_data


def get_addr_state(addr: bytes) -> AddressState:
    stub = get_public_stub()
    response = stub.GetAddressState(request=qrl_pb2.GetAddressStateReq(address=addr))
    return AddressState(response.state)


def set_unused_ots_key(xmss, addr_state, start=0):
    for i in range(start, 2 ** xmss.height):
        if not addr_state.ots_key_reuse(i):
            xmss.set_ots_index(i)
            return True
    return False


def valid_payment_permission(public_stub, master_address_state, payment_xmss, json_slave_txn):
    access_type = master_address_state.get_slave_permission(payment_xmss.pk)

    if access_type == -1:
        tx = Transaction.from_json(json_slave_txn)
        public_stub.PushTransaction(request=qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata))
        return None

    if access_type == 0:
        return True

    return False


def get_unused_payment_xmss(public_stub):
    global payment_slaves
    global payment_xmss

    master_address = payment_slaves[0]
    master_address_state = get_addr_state(master_address)

    if payment_xmss:
        addr_state = get_addr_state(payment_xmss.address)
        if set_unused_ots_key(payment_xmss, addr_state, payment_xmss.ots_index):
            if valid_payment_permission(public_stub, master_address_state, payment_xmss, payment_slaves[2]):
                return payment_xmss
        else:
            payment_xmss = None

    if not payment_xmss:
        unused_ots_found = False
        for slave_seed in payment_slaves[1]:
            xmss = XMSS.from_extended_seed(slave_seed)
            addr_state = get_addr_state(xmss.address)
            if set_unused_ots_key(xmss, addr_state):  # Unused ots_key_found
                payment_xmss = xmss
                unused_ots_found = True
                break

        if not unused_ots_found:  # Unused ots_key_found
            return None

    if not valid_payment_permission(public_stub, master_address_state, payment_xmss, payment_slaves[2]):
        return None

    return payment_xmss


@app.route('/api/<api_method_name>')
def api_proxy(api_method_name):
    """
    Proxy JSON RPC requests to the gRPC server as well as converts back gRPC response
    to JSON.
    :param api_method_name:
    :return:
    """
    stub = qrl_pb2_grpc.PublicAPIStub(grpc.insecure_channel('{}:{}'.format(config.user.public_api_host,
                                                                           config.user.public_api_port),
                                                            options=[('grpc.max_receive_message_length', 10485760)]))
    public_api = qrl_pb2.DESCRIPTOR.services_by_name['PublicAPI']
    api_method = public_api.FindMethodByName(api_method_name)
    api_request = getattr(qrl_pb2, api_method.input_type.name)()

    for arg in request.args:
        if arg not in api_method.input_type.fields_by_name:
            raise Exception('Invalid args %s', arg)
        data_type = type(getattr(api_request, arg))
        if data_type == bool and request.args[arg].lower() == 'false':
            continue
        value = data_type(request.args.get(arg, type=data_type))
        setattr(api_request, arg, value)

    resp = getattr(stub, api_method_name)(api_request, timeout=10)
    return Response(response=MessageToJson(resp, sort_keys=True), status=200, mimetype='application/json')


def get_mining_stub():
    global mining_stub
    return mining_stub


def get_public_stub():
    global public_stub
    return public_stub


@api.dispatcher.add_method
def getlastblockheader(height=0):
    stub = get_mining_stub()
    request = qrlmining_pb2.GetLastBlockHeaderReq(height=height)
    grpc_response = stub.GetLastBlockHeader(request=request, timeout=10)

    block_header = {
        'difficulty': grpc_response.difficulty,
        'height': grpc_response.height,
        'timestamp': grpc_response.timestamp,
        'reward': grpc_response.reward,
        'hash': grpc_response.hash,
        'depth': grpc_response.depth
    }

    resp = {
        "block_header": block_header,
        "status": "OK"
    }
    return resp


@api.dispatcher.add_method
def getblockheaderbyheight(height):
    return getlastblockheader(height)


@api.dispatcher.add_method
def getblocktemplate(reserve_size, wallet_address):
    stub = get_mining_stub()
    request = qrlmining_pb2.GetBlockToMineReq(wallet_address=wallet_address.encode())
    grpc_response = stub.GetBlockToMine(request=request, timeout=10)
    resp = {
        'blocktemplate_blob': grpc_response.blocktemplate_blob,
        'difficulty': grpc_response.difficulty,
        'height': grpc_response.height,
        'reserved_offset': grpc_response.reserved_offset,
        'seed_hash': grpc_response.seed_hash,
        'status': 'OK'
    }

    return resp


@api.dispatcher.add_method
def getbalance():
    stub = get_public_stub()
    grpc_response = stub.GetOptimizedAddressState(request=qrl_pb2.GetAddressStateReq(address=payment_slaves[0]))
    return grpc_response.state.balance


@api.dispatcher.add_method
def getheight():
    stub = get_public_stub()
    grpc_response = stub.GetHeight(request=qrl_pb2.GetHeightReq())

    resp = {'height': grpc_response.height}
    return resp


@api.dispatcher.add_method
def submitblock(blob):
    stub = get_mining_stub()
    request = qrlmining_pb2.SubmitMinedBlockReq(blob=bytes(hstr2bin(blob)))
    response = stub.SubmitMinedBlock(request=request, timeout=10)
    if response.error:
        raise Exception  # Mining pool expected exception when block submission fails
    return {'status': 'OK', 'error': 0}


@api.dispatcher.add_method
def getblockminingcompatible(height):
    stub = get_mining_stub()
    request = qrlmining_pb2.GetBlockMiningCompatibleReq(height=height)
    response = stub.GetBlockMiningCompatible(request=request, timeout=10)
    return MessageToJson(response, sort_keys=True)


@api.dispatcher.add_method
def transfer(destinations, fee, mixin, unlock_time):
    if len(destinations) > config.dev.transaction_multi_output_limit:
        raise Exception('Payment Failed: Amount exceeds the allowed limit')

    addrs_to = []
    amounts = []

    for tx in destinations:
        addrs_to.append(bytes(hstr2bin(tx['address'][1:])))  # Skipping 'Q'
        amounts.append(tx['amount'])

    stub = get_public_stub()

    xmss = get_unused_payment_xmss(stub)
    if not xmss:
        raise Exception('Payment Failed: No Unused Payment XMSS found')

    tx = TransferTransaction.create(addrs_to=addrs_to,
                                    amounts=amounts,
                                    message_data=None,
                                    fee=fee,
                                    xmss_pk=xmss.pk,
                                    master_addr=payment_slaves[0])

    tx.sign(xmss)

    response = stub.PushTransaction(request=qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata))

    if response.error_code != 3:
        raise Exception('Transaction Submission Failed, Response Code: %s', response.error_code)

    response = {'tx_hash': bin2hstr(tx.txhash)}

    return response


app.add_url_rule('/json_rpc', 'api', api.as_view(), methods=['POST'])


def parse_arguments():
    parser = argparse.ArgumentParser(description='QRL node')
    parser.add_argument('--qrldir', '-d', dest='qrl_dir', default=config.user.qrl_dir,
                        help="Use a different directory for node data/configuration")
    parser.add_argument('--network-type', dest='network_type', choices=['mainnet', 'testnet'],
                        default='mainnet', required=False, help="Runs QRL Testnet Node")
    return parser.parse_args()


def main():
    args = parse_arguments()

    qrl_dir_post_fix = ''
    copy_files = []
    if args.network_type == 'testnet':
        qrl_dir_post_fix = '-testnet'
        package_directory = os.path.dirname(os.path.abspath(__file__))
        copy_files.append(os.path.join(package_directory, 'network/testnet/genesis.yml'))
        copy_files.append(os.path.join(package_directory, 'network/testnet/config.yml'))

    config.user.qrl_dir = os.path.expanduser(os.path.normpath(args.qrl_dir) + qrl_dir_post_fix)
    config.create_path(config.user.qrl_dir, copy_files)
    config.user.load_yaml(config.user.config_path)

    global payment_slaves, payment_xmss
    global mining_stub, public_stub
    mining_stub = qrlmining_pb2_grpc.MiningAPIStub(grpc.insecure_channel('{0}:{1}'.format(config.user.mining_api_host,
                                                                                          config.user.mining_api_port)))
    public_stub = qrl_pb2_grpc.PublicAPIStub(grpc.insecure_channel('{0}:{1}'.format(config.user.public_api_host,
                                                                                    config.user.public_api_port),
                                                                   options=[('grpc.max_receive_message_length',
                                                                             10485760)]))
    payment_xmss = None
    payment_slaves = read_slaves(config.user.mining_pool_payment_wallet_path)
    app.run(host=config.user.grpc_proxy_host, port=config.user.grpc_proxy_port, threaded=False)


if __name__ == '__main__':
    main()
