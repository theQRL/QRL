var grpc = require('grpc');
var temp = require('temp').track();
var fs = require('fs');

function fetchRemoteProto(node_addr, callback) {
    var protoDescriptor = grpc.load('../../qrl/protos/qrlbase.proto');

    client = new protoDescriptor.qrl.Base(node_addr, grpc.credentials.createInsecure());

    client.getNodeInfo({}, function (err, nodeInfo) {
        if (err) {
            console.log(err);
            // TODO: Handle errors, etc
            return;
        }

        // TODO: Check version, etc.

        console.log(nodeInfo.version);
//        console.log(nodeInfo.grpcProto);

        // TODO: Load protoDescription from string directly
        // At the moment, only loads from a file..
        temp.track();
        temp.open('proto', function (err, info) {
            if (!err) {
                fs.write(info.fd, nodeInfo.grpcProto);
                fs.close(info.fd, function (err) {
                    var remoteProtoDescriptor = grpc.load(info.path);
                    console.log('ready');
                });
            }
        });
    });
}

var protoDescriptor = fetchRemoteProto('localhost:9009');
