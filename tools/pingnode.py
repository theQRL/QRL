from __future__ import print_function

import grpc

from qrl.generated.qrl_pb2 import GetNodeStateReq
from qrl.generated.qrl_pb2_grpc import P2PNodeStub


def run():
    channel = grpc.insecure_channel('localhost:9009')
    stub = P2PNodeStub(channel)
    response = stub.GetNodeState(GetNodeStateReq())
    print("answer received: " + response.message)


if __name__ == '__main__':
    run()
