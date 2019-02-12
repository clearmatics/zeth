var PROTO_PATH = __dirname + '/test.proto';
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
var test = protoDescriptor.test;

function main() {
    // We instantiate the TestService from the test package
    var client = new test.TestService('localhost:50051',
                                         grpc.credentials.createInsecure());

    client.ping({content: "Content request", code: 10}, function(err, response) {
      console.log('Response content:', response.content);
      console.log('Response code:', response.code);
    });
  }
  
  main();