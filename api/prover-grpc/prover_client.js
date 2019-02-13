var PROTO_PATH = __dirname + '/prover.proto';
var grpc = require('grpc');
var protoLoader = require('@grpc/proto-loader');
// Suggested options for similarity to existing grpc.load behavior
var packageDefinition = protoLoader.loadSync(
  PROTO_PATH,
  {keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });
var protoDescriptor = grpc.loadPackageDefinition(packageDefinition);

// The protoDescriptor object has the full package hierarchy
// Here we access the test package (test being the name of the unique package in the proto file) defined in the proto file
var prover = protoDescriptor.proverpkg;

function main() {
  // We instantiate the TestService from the test package
  var client = new prover.Prover('0.0.0.0:50051',
    grpc.credentials.createInsecure());

  //client.runSetup({}, function(err, response) {
  //  console.log('Sent request to run the setup');
  //});

  // First call to client.prove() [DEBUG]
//  {
//    var root = "ROOT";
//    var JSInputs1 = [{
//      merkleNode: ["node1", "node2"],
//      address: 7,
//      note: {
//        aPK: "apk",
//        value: 22,
//        rho: "rho",
//        trapR: "trapR"
//      },
//      spendingASK: "spendingASK",
//      nullifier: "nullifier"
//    }];
//
//    var outCommitments = [{
//      aPK: "outAPK",
//        value: 99,
//        rho: "outRHO",
//        trapR: "outR"
//    }];
//
//    var inPubValue = "inPubVal";
//    var outPubValue = "outPubVal";
//
//
//    client.prove({
//      root: root,
//      inNullifiers: JSInputs1,
//      outCommitments: outCommitments,
//      inPubValue: inPubValue,
//      outPubValue: outPubValue
//    }, function(err, response) {
//      console.log('Sent request to PROVE');
//    });
//  }

  // Second call to client.prove with digest data
  {
    var root = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
    var JSInputs1 = [{
      merkleNode: [
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b", 
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
      ],
      address: 7,
      note: {
        aPK: "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        value: "2F0000000000000F",
        rho: "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
        trapR: "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF" // 48
      },
      spendingASK: "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
      nullifier: "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
    }];

    var jsOutputs1 = [{
      aPK: "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
      value: "2F0000000000000F",
      rho: "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
      trapR: "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF00000000000000FF"
    }];

    var inPubValue = "2F0000000000000F";
    var outPubValue = "2F0000000000000F";


    client.prove({
      root: root,
      jsInputs: JSInputs1,
      jsOutputs: jsOutputs1,
      inPubValue: inPubValue,
      outPubValue: outPubValue
    }, function(err, response) {
      console.log('Sent request to PROVE');
    });
  }
}

main();
