#!/usr/bin/env bash
pushd . > /dev/null
cd $( dirname "${BASH_SOURCE[0]}" )
cd ..

python -m grpc_tools.protoc -I=qrl/protos --python_out=qrl/generated --grpc_python_out=qrl/generated qrl/protos/qrl.proto
python -m grpc_tools.protoc -I=qrl/protos/qrl.proto -I=qrl/protos --python_out=qrl/generated --grpc_python_out=qrl/generated qrl/protos/qrllegacy.proto
python -m grpc_tools.protoc -I=qrl/protos --python_out=qrl/generated --grpc_python_out=qrl/generated qrl/protos/qrlbase.proto
python -m grpc_tools.protoc -I=qrl/protos --python_out=qrl/generated --grpc_python_out=qrl/generated qrl/protos/qrlmining.proto

# Patch import problem in generated code
sed -i 's|import qrl_pb2 as qrl__pb2|import qrl.generated.qrl_pb2 as qrl__pb2|g' qrl/generated/qrl_pb2_grpc.py
sed -i 's|import qrl_pb2 as qrl__pb2|import qrl.generated.qrl_pb2 as qrl__pb2|g' qrl/generated/qrllegacy_pb2.py
sed -i 's|import qrl_pb2 as qrl__pb2|import qrl.generated.qrl_pb2 as qrl__pb2|g' qrl/generated/qrlmining_pb2.py

sed -i 's|import qrllegacy_pb2 as qrllegacy__pb2|import qrl.generated.qrllegacy_pb2 as qrllegacy__pb2|g' qrl/generated/qrllegacy_pb2_grpc.py
sed -i 's|import qrlbase_pb2 as qrlbase__pb2|import qrl.generated.qrlbase_pb2 as qrlbase__pb2|g' qrl/generated/qrlbase_pb2_grpc.py
sed -i 's|import qrlmining_pb2 as qrlmining__pb2|import qrl.generated.qrlmining_pb2 as qrlmining__pb2|g' qrl/generated/qrlmining_pb2_grpc.py

find qrl/generated -name '*.py'|grep -v migrations|xargs autoflake --in-place

#docker run --rm \
#  -v $(pwd)/docs/proto:/out \
#  -v $(pwd)/qrl/protos:/protos \
#  pseudomuto/protoc-gen-doc --doc_opt=markdown,proto.md
#
#docker run --rm \
#  -v $(pwd)/docs/proto:/out \
#  -v $(pwd)/qrl/protos:/protos \
#  pseudomuto/protoc-gen-doc --doc_opt=html,index.html

popd > /dev/null
