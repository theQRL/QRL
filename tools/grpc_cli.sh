#!/usr/bin/env bash
SCRIPT_DIR=$( dirname "${BASH_SOURCE[0]}" )
PROJECT_DIR=$( readlink -f ${SCRIPT_DIR}/.. )
PROTO_DIR=$( readlink -f ${PROJECT_DIR}/qrl/protos )

echo "PROJECT_DIR = ${PROJECT_DIR}"
echo "PROTOFILE   = ${PROTOFILE}"

# UGLY workaround until include paths are supported by grpcc
TIMESTAMP_FILES=$(locate google/protobuf/timestamp.proto)
TIMESTAMP_ARR=($TIMESTAMP_FILES)
mkdir -p ${PROTO_DIR}/google/protobuf/
cp ${TIMESTAMP_ARR} ${PROTO_DIR}/google/protobuf/timestamp.proto

pushd .
cd ${PROTO_DIR}
grpcc -i -p qrl.proto -a localhost:9009
popd