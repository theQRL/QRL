from __future__ import print_function

import grpc

from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2 import PingReq


def run():
    channel = grpc.insecure_channel('localhost:9009')
    stub = qrl_pb2.P2PNodeStub(channel)
    response = stub.Ping(PingReq(name='client'))
    print("answer received: " + response.message)


if __name__ == '__main__':
    run()
