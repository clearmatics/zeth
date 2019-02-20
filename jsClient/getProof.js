const Web3 = require('web3');
const fs = require('fs');
const path = require('path');

// Zeth module that contains utils to parse the prover
// responses and format the client's requests
const zeth = require('./zeth-utils');

// gRPC config
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
// The protoDescriptor object has the full package hierarchy
var protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
var prover = protoDescriptor.proverpkg;

if (typeof web3 !== 'undefined') {
	web3 = new Web3(web3.currentProvider);
} else {
	// Set the provider you want from Web3.providers
	web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"))
}

const keystore = zeth.initTestKeystore();
const zeroWei = "0000000000000000000"; // web3.utils.toWei('0', 'ether') returns 0 and not "0000000000000000000"!
const zeroWeiHex = "0000000000000000";

function BobDepositsForHimself(client) {
	console.log(" ==== [Test case 1] Bob deposits 7ETH for himself in the mixer ==== ");
	var bobAPK = keystore.Bob.AddrPk.a_pk; // we generate a coin for Bob (recipient)
	var bobASK = keystore.Bob.AddrSk.a_sk; // Bob is the spending authority

	var noteBobIn = zeth.createZethNote(zeth.noteRandomness(), bobAPK, zeroWeiHex);
	var commitmentIn = zeth.computeCommitment(noteBobIn);
	var nullifierIn = zeth.computeNullifier(noteBobIn, bobASK);

  console.log("[DEBUG] HERE 1");
  // Erroneous merkle path, but this is fine as membership in the merkle tree is
  // not checked because we have a coin of denomination 0
	var root = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";
  var merklePath = [
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
	];

	var jsInputs = [
    zeth.createJSInput(merklePath, 7, noteBobIn, bobASK, nullifierIn)
  ];

  console.log("[DEBUG] HERE 2");
	// Note that the value FFFFFFFFFFFFFFF  in hex corresponds to 18446744073709551615 wei
	// which is a little above 18ETH. If this not enough, we can use another unit for the value
	//
	// For this PoC, we will stick to Wei as a unit for the value as we do not care about
	// transacting big values
	//
	// Generate coin (value 0) for a deposit: Input of the JS
	var valueOut = zeth.decimalToHexadecimal(web3.utils.toWei('7', 'ether').toString()); // Note of value 7 as output of the JS
	var noteBobOut = zeth.createZethNote(zeth.noteRandomness(), bobAPK, valueOut);
	var commitmentOut = zeth.computeCommitment(noteBobOut);
	var nullifierOut = zeth.computeNullifier(noteBobOut, bobASK);

	var jsOutputs = [
    noteBobOut
  ];

  // Needs to match the value of output note if we want to sat. the constraints
  var inPubValue = zeth.decimalToHexadecimal(web3.utils.toWei('7', 'ether').toString());
  var outPubValue = zeroWeiHex; // No pub output

  console.log("[DEBUG] HERE 3");
	var proofInputs = {
		root: root,
		jsInputs: jsInputs,
		jsOutputs: jsOutputs,
		inPubValue: inPubValue,
		outPubValue: outPubValue
	};

  // RPC call to the prover
  console.log("[DEBUG] Send request to generate a proof");
  client.prove(proofInputs, function(err, response) {
    console.log("[DEBUG] Enter the callback");
    if (err) {
      console.log("[ERROR] " + err);
      return;
    }

    console.log("[DEBUG] Received proof");
    console.log("[DEBUG] Parsing the proof...");
    var result_proof = {
      a: zeth.parseHexadecimalPointBaseGroup1Affine(response.a),
      a_p: zeth.parseHexadecimalPointBaseGroup1Affine(response.aP),
      b: zeth.parseHexadecimalPointBaseGroup2Affine(response.b),
      b_p: zeth.parseHexadecimalPointBaseGroup1Affine(response.bP),
      c: zeth.parseHexadecimalPointBaseGroup1Affine(response.c),
      c_p: zeth.parseHexadecimalPointBaseGroup1Affine(response.cP),
      h: zeth.parseHexadecimalPointBaseGroup1Affine(response.h),
      k: zeth.parseHexadecimalPointBaseGroup1Affine(response.k),
      input: JSON.parse(response.inputs)
    };
    console.log("[INFO] Proof fetched from the proving service");
    console.log("[INFO] Writing the proof in a file...");
    var debug_path = process.env.ZETH_DEBUG_DIR;
    var test_proof_json = path.join(debug_path, "test_proof_bob_deposits_for_himself.json");
    fs.writeFileSync(test_proof_json, JSON.stringify(result_proof));
  });

  return;
}

function main() {
	// Create a client RPC instance used across all test cases
  var client = new prover.Prover('0.0.0.0:50051', grpc.credentials.createInsecure());
  var proof = BobDepositsForHimself(client);
}

main();
