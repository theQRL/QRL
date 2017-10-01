#!/usr/bin/env bash
python -m grpc_tools.protoc -I=qrl/protos --python_out=qrl/generated --grpc_python_out=qrl/generated qrl/protos/qrl.proto
