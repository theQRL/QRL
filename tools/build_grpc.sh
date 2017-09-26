#!/usr/bin/env bash
pushd . > /dev/null
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd ..

python -m grpc_tools.protoc -I=qrl/protos --python_out=qrl/generated --grpc_python_out=qrl/generated qrl/protos/qrl.proto

# Patch import problem in generated code
sed -i 's|import qrl_pb2 as qrl__pb2|import qrl.generated.qrl_pb2 as qrl__pb2|g' qrl/generated/qrl_pb2_grpc.py

popd > /dev/null
