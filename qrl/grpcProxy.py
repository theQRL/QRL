# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import grpc
from google.protobuf.json_format import MessageToJson

from qrl.generated import qrl_pb2_grpc, qrl_pb2
from flask import Flask, Response, request

app = Flask(__name__)


@app.route('/api/<api_method_name>')
def api_proxy(api_method_name):
    """
    Proxy JSON RPC requests to the gRPC server as well as converts back gRPC response
    to JSON.
    TODO :
    1.  Remove hardcoded Server IP and Port
    2.  Include MiningAPIServices too
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


if __name__ == '__main__':
    app.run(port=18081)
