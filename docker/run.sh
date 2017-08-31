#!/usr/bin/env bash
docker build -t qrl .
#docker run -t --name node1  qrl

# Start 4 nodes
docker run -dt --name node1  qrl
docker run -dt --name node2  qrl
docker run -dt --name node3  qrl
docker run -dt --name node4  qrl
