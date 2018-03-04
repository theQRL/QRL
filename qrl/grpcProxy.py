# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import grpc
from google.protobuf.json_format import MessageToJson
from pyqrllib.pyqrllib import hstr2bin

from qrl.generated import qrl_pb2_grpc, qrl_pb2, qrlmining_pb2, qrlmining_pb2_grpc
from flask import Flask, Response, request
from jsonrpc.backend.flask import api

app = Flask(__name__)


@app.route('/api/<api_method_name>')
def api_proxy(api_method_name):
    """
    Proxy JSON RPC requests to the gRPC server as well as converts back gRPC response
    to JSON.
    TODO :
    1.  Remove hardcoded Server IP and Port
    :param api_method_name:
    :return:
    """
    stub = qrl_pb2_grpc.PublicAPIStub(grpc.insecure_channel('127.0.0.1:9009'))
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
    return Response(response=MessageToJson(resp), status=200, mimetype='application/json')


def get_mining_stub():
    stub = qrlmining_pb2_grpc.MiningAPIStub(grpc.insecure_channel('127.0.0.1:9007'))
    return stub


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
        'hash': grpc_response.hash
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
def getblocktemplate(wallet_address):
    stub = get_mining_stub()
    request = qrlmining_pb2.GetBlockToMineReq(wallet_address=wallet_address.encode())
    grpc_response = stub.GetBlockToMine(request=request, timeout=10)
    resp = {
        'blocktemplate_blob': grpc_response.blocktemplate_blob,
        'difficulty': grpc_response.difficulty,
        'height': grpc_response.height,
        'status': 'OK'
    }

    return resp


@api.dispatcher.add_method
def submitblock(blob):
    stub = get_mining_stub()
    request = qrlmining_pb2.SubmitMinedBlockReq(blob=bytes(hstr2bin(blob)))
    response = stub.SubmitMinedBlock(request=request, timeout=10)
    return MessageToJson(response)


@api.dispatcher.add_method
def getblockminingcompatible(height):
    stub = get_mining_stub()
    request = qrlmining_pb2.GetBlockMiningCompatibleReq(height=height)
    response = stub.GetBlockMiningCompatible(request=request, timeout=10)
    return MessageToJson(response)


app.add_url_rule('/json_rpc', 'api', api.as_view(), methods=['POST'])

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=18081)
