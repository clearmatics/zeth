const Web3 = require('web3');
const zeth = require('./zeth-utils');

var PROTO_PATH = __dirname + '/api/prover-grpc/prover.proto';
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

function getProof() {
	// Create a client RPC instance to delegate proof generations to the Prover
  var client = new prover.Prover('0.0.0.0:50051', grpc.credentials.createInsecure());

	console.log("[Test case 1] Bob deposits for himself in the mixer");

	// Note that the value FFFFFFFFFFFFFFF  in hex corresponds to 18446744073709551615 wei
	// which is a little above 18ETH. If this not enough, we can use another unit for the value
	//
	// For this PoC, we will stick to Wei as a unit for the value as we do not care about
	// transacting big values
	//
	// Generate coin (value 0) for a deposit: Input of the JS
  ////////

	var randomnessIn = zeth.noteRandomness(); // rho and trapR for the coin
	var BobAPK = keystore.Bob.AddrPk.a_pk; // we generate a coin for Bob (recipient)
	var valueIn = zeroWeiHex; // Dummy note (val = 0)
	var noteBobIn = zeth.createZethNote(randomnessIn, BobAPK, valueIn);
	var commitmentIn = zeth.computeCommitment(noteBobIn);
	var BobASK = keystore.Bob.AddrSk.a_sk; // Bob is the spending authority
	var nullifierIn = zeth.computeNullifier(noteBobIn, BobASK);

	console.log("[DEBUG] Display coin's data");
	console.log(`Apk: ${zeth.hexFmt(noteBobIn.apk)}`);
	console.log(`Rho: ${zeth.hexFmt(noteBobIn.rho)}`);
	console.log(`Value: ${zeth.hexFmt(noteBobIn.value)}`);
	console.log(`TrapR: ${zeth.hexFmt(noteBobIn.trapR)}`);
	console.log(`Commitment: ${zeth.hexFmt(commitmentIn)}`);

  // Erronoeus merkle path, but this is fine as membership in the merkle tree is
  // not checked because we have a coin of denomination 0
  var merklePath = [
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b",
		"6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b"
	];

	var jsInputs = [
    {
      merkleNode: merklePath,
      address: 7,
      note: noteBobIn,
      spendingASK: BobASK,
      nullifier: nullifierIn
	  }
  ];
	console.log(`Note.Apk: ${jsInputs[0].note.apk}`);

	var randomnessOut = zeth.noteRandomness(); // rho and trapR for the coin
	var valueOut = zeth.decimalToHexadecimal(web3.utils.toWei('7', 'ether').toString()); // Obfuscated note of value 7 as output of the deposit
	var noteBobOut = zeth.createZethNote(randomnessOut, BobAPK, valueOut);
	var commitmentOut = zeth.computeCommitment(noteBobOut);
	var nullifierOut = zeth.computeNullifier(noteBobOut, BobASK);

	var jsOutputs = [
    noteBobOut
  ];

  // Needs to match the value of output note if we want to sat. the constraints
  var inPubValue = zeth.decimalToHexadecimal(web3.utils.toWei('7', 'ether').toString());
  var outPubValue = zeroWeiHex; // No pub output

  console.log("Value in pub: " + inPubValue);
  console.log("Value out pub: " + outPubValue);

  // Some random data -> Doesn't satisfy the constraints of the circuit
	var root = "6461f753bfe21ba2219ced74875b8dbd8c114c3c79d7e41306dd82118de1895b";

	var proofInputs = {
		root: root,
		jsInputs: jsInputs,
		jsOutputs: jsOutputs,
		inPubValue: inPubValue,
		outPubValue: outPubValue
	};

  console.log("proofInputs ==> ");
  console.log(proofInputs);

	// RPC call to the prover
  console.log("Send request to generate a proof");
  client.prove(proofInputs, function(err, response) {
    console.log('Sent request to PROVE');
    console.log("Received response: ==> ");
    console.log("Response ===> ");
    console.log(response);

    console.log("JSON Parsed response ===> ");
    var ext_proof_a = [response.a.xCoord, response.a.yCoord]";
    var ext_proof_ap = [response.aP.xCoord, response.aP.yCoord];
    var ext_proof_b = [[response.b.xC1Coord, response.b.xC0Coord], [response.b.yC1Coord, response.b.yC0Coord]];
    var ext_proof_bp = [response.bP.xCoord, response.bP.yCoord];
    var ext_proof_c = [response.c.xCoord, response.c.yCoord];
    var ext_proof_cp = [response.cP.xCoord, response.cP.yCoord];
    var ext_proof_h = [response.h.xCoord, response.h.yCoord];
    var ext_proof_k = [response.k.xCoord, response.k.yCoord];
    var ext_proof_inputs = response.inputs;

    // Try to call the verify contract on-chain
  });
}

// Get the verification key
function main() {
	// Create a client RPC instance to delegate proof generations to the Prover
  var client = new prover.Prover('0.0.0.0:50051', grpc.credentials.createInsecure());

	// RPC call to the prover to fetch the verification key
  console.log("Send request to fetch the verification key");
  client.getVerificationKey({}, function(err, response) {
    console.log('Sent request to Get the verification key');
    console.log("Response ===> ");
    console.log(response);
  });
}


main();
