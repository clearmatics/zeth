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

    client.runSetup({}, function(err, response) {
      console.log('Sent request to run the setup');
    });
  }

  main();
