// README: This is ECMAScript6 code! Update your settings if you see warnings

let grpc = require('grpc');
let temp = require('temp').track();
let fs = require("fs-extra");

async function fetchRemoteProto(node_addr) {
    let protoDescriptor = grpc.load('../../qrl/protos/qrlbase.proto');
    let client = new protoDescriptor.qrl.Base(node_addr, grpc.credentials.createInsecure());

    return new Promise(resolve => {
        client.getNodeInfo({}, function (err, nodeInfo) {
            if (err) throw err;    // TODO: Handle errors, etc

            // TODO: Check version, etc.

            // WORKAROUND: Copy timestamp  (I am investigating how to avoid this step)
            let req_file = '/tmp/google/protobuf/timestamp.proto';
            if (!fs.existsSync(req_file))
            {
                fs.ensureDirSync('/tmp/google/protobuf');
                fs.copySync('timestamp.proto', req_file, { overwrite : true });
            }

            // At the moment, we can only load from a file..
            temp.open('proto', function (err, info) {
                if (!err) {
                    fs.write(info.fd, nodeInfo.grpcProto);
                    fs.close(info.fd, function () {
                        let remoteProtoDescriptor = grpc.load(info.path);
                        resolve(remoteProtoDescriptor);
                    });
                }
            });
        });
    });
}

async function getQRLClient(node_addr) {
    return new Promise(resolve => {
        const remoteProto = fetchRemoteProto(node_addr);
        remoteProto.then(function (remoteProto) {
            let client = new remoteProto.qrl.PublicAPI(node_addr, grpc.credentials.createInsecure());
            resolve(client);
        });
    });
}

// NOTE: Avoid creating the client many times..
// NOTE: gRPC uses HTTP2 so ideally there should be a single persistent connection
let qrlClient = getQRLClient('localhost:9009');

qrlClient.then( function (qrlClient) {

    // TODO: Normal logic should be based on async/await like what I did in getQRLClient / fetchRemoteProto
    // This is just a short example

    // Get local address state
    qrlClient.getAddressStateLocal({address_idx: 0}, function (err, response) {
        if (err) {
            console.log("Error: ", err.message);
            return;
        }

        // No need to use dictionaries, etc
        console.log("Address: %s        Balance: %d", response.state.address, response.state.balance);
    });

    // Get some genesis address state
    qrlClient.getAddressState({address : 'Qada446e9ac25b11299e0615de8bd1b7f5404ce0052fbb27db7ada425904a5aea6063deb3'}, function (err, response){
        if (err){
            console.log("Error: ", err.message);
            return;
        }

        console.log("Address: %s        Balance: %d", response.state.address, response.state.balance);
    });

});
