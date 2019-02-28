const Web3 = require('web3');
const fs = require('fs');
const path = require('path');

// Zeth module that contains utils to parse the prover
// responses and format the client's requests
const zeth = require('./zeth-utils');

var api_path = process.env.ZETH_API_DIR;
var prover_proto = path.join(api_path, "prover.proto");
var grpc = require('grpc');
var protoLoader = require('@grpc/proto-loader');
// Suggested options for similarity to existing grpc.load behavior
var packageDefinition = protoLoader.loadSync(
  prover_proto,
  {keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });
var protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
// The protoDescriptor object has the full package hierarchy
var prover = protoDescriptor.proverpkg;

if (typeof web3 !== 'undefined') {
	web3 = new Web3(web3.currentProvider);
} else {
	// Set the provider you want from Web3.providers
	web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"))
}

function parseHexadecimalPointBaseGroup2Affine(point) {
	return [
		[point.xC1Coord, point.xC0Coord],
		[point.yC1Coord, point.yC0Coord]
	];
}

function parseHexadecimalPointBaseGroup1Affine(point) {
	return [point.xCoord, point.yCoord];
}

// Get the verification key from the proving service
function getVerificationKey() {
  var client = new prover.Prover('0.0.0.0:50051', grpc.credentials.createInsecure());

  // RPC call to the prover to fetch the verification key
  console.log("[DEBUG] Send request to fetch the verification key");
  client.getVerificationKey({}, function(err, response) {
    if (err) {
      console.log("[ERROR] " + err);
      return;
    }

    console.log("[DEBUG] Received verification key from server");
    console.log("[DEBUG] Parsing the key...");
    var vk_obj = {
      a: parseHexadecimalPointBaseGroup2Affine(response.a),
      b: parseHexadecimalPointBaseGroup1Affine(response.b),
      c: parseHexadecimalPointBaseGroup2Affine(response.c),
      g: parseHexadecimalPointBaseGroup2Affine(response.g),
      gb1: parseHexadecimalPointBaseGroup1Affine(response.gb1),
      gb2: parseHexadecimalPointBaseGroup2Affine(response.gb2),
      z: parseHexadecimalPointBaseGroup2Affine(response.z),
      IC: JSON.parse(response.IC)
    };

    console.log("[DEBUG] Writing the key in file");
    var setup_path = process.env.ZETH_TRUSTED_SETUP_DIR;
    var vk_json = path.join(setup_path, "vk.json");
    fs.writeFileSync(vk_json, JSON.stringify(vk_obj));
  });
}

function main() {
  getVerificationKey();
}

main();
