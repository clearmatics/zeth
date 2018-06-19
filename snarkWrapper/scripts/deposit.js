var Web3 = require('web3');
var Solidity = require('solc');
var fs = require("fs");
var BigNumber = require('bignumber.js');
const leftPad = require('left-pad');

var input = {
    'Miximus.sol': fs.readFileSync("../contracts/Miximus.sol", "utf8"),
    'Verifier.sol': fs.readFileSync("../contracts/Verifier.sol", "utf8"), 
    'MerkleTree.sol': fs.readFileSync("../contracts/MerkleTree.sol", "utf8"),
    'Pairing.sol': fs.readFileSync("../contracts/Pairing.sol", "utf8")
}

// Compilation of the smart contracts
var compiled = Solidity.compile({sources: input}, 1)
console.log(compiled);

// Accessing the ABIs of the contracts
var verifier_abi = compiled.contracts["Verifier.sol:Verifier"].interface;
var miximus_abi = compiled.contracts["Miximus.sol:Miximus"].interface;

var verifier_abi = JSON.parse(verifier_abi);
var miximus_abi = JSON.parse(miximus_abi);

if (typeof web3 !== 'undefined') {
    web3 = new Web3(web3.currentProvider);
} else {
    // Set the provider you want from Web3.providers
    web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
}

var verifier = web3.eth.contract(verifier_abi);
var miximus = web3.eth.contract(miximus_abi);

// Lines to be edited by the user
var verifierContractAddress = "0x27016182e9136f60b48497fff50abf8098bc2171";
var miximusContractAddress = "0xa723649175e8c13796ab2cb52fc1e3972c41f6e2";

var verifier_deployed = verifier.at(verifierContractAddress);
var miximus_deployed = miximus.at(miximusContractAddress);

var sender = web3.eth.accounts[0];
var recipient = web3.eth.accounts[1];

// Lines to be edited by the user
nullifier = recipient + "FFFFFFFFFFFFFFFFFFFFFFFA"; // Computes a nullifier from the recipient address
console.log("[DEBUG] Nullifier value: ", nullifier);
sk = "0xc9b94d9a757f6a57e38809be7dca7599fb0d1bb5ee6b2e7c685092dd8b5e71db";
// miximus_deployed.getSha256(nullifier, sk)
// Action of the user
// Compute the sha256 of (nullifier || sk)
var leaf = 0x963b94817fa67b548cde1692d1ffce2a2f7faf100763635bfc814f89066a9be0;
console.log("[DEBUG] Leaf to insert: ", leaf, " computed from: ", nullifier, sk);

console.log(" --- [DEBUG] Balances BEFORE deposit --- ");
console.log("Sender: ", web3.eth.getBalance(sender));
console.log("Recipient: ", web3.eth.getBalance(recipient));
console.log("Mixer: ", web3.eth.getBalance(miximus_deployed.address));
miximus_deployed.deposit(leaf, {from:sender, gas: 6000000, value:web3.toWei(1,"ether")}, function(err, success) {
    console.log(" --- [DEBUG] Balances AFTER deposit --- ");
    console.log("Sender: ", web3.eth.getBalance(sender));
    console.log("Recipient: ", web3.eth.getBalance(recipient));
    console.log("Mixer: ", web3.eth.getBalance(miximus_deployed.address));

    var tree = miximus_deployed.getTree();
    console.log("[DEBUG] Get Merkle Tree: ", tree);
    console.log(" --- [DEBUG] Merkle path in binary: --- ");
    leaf = new BigNumber(tree[16], 16).toString(2).split("").join(" ,");
    node17 = new BigNumber(tree[17], 16).toString(2).split("").join(" ,");
    node9 = new BigNumber(tree[9], 16).toString(2).split("").join(" ,");
    node5 = new BigNumber(tree[5], 16).toString(2).split("").join(" ,");
    node3 = new BigNumber(tree[3], 16).toString(2).split("").join(" ,");
    root = new BigNumber(tree[1], 16).toString(2).split("").join(" ,");
    cm = new BigNumber(nullifier, 16).toString(2).split("").join(" ,");
    secret = new BigNumber(sk, 16).toString(2).split("").join(" ,");
    console.log(
        "libff::bit_vector node17 = {", node17, "};\n" ,
        "libff::bit_vector node16 = {", leaf, "};\n" ,
        "libff::bit_vector node9 = {", node9, "};\n",
        "libff::bit_vector node5 = {", node5, "};\n",
        "libff::bit_vector node3 = {", node3, "};\n",
        "libff::bit_vector node_root = {", root, "};\n",
        "libff::bit_vector nullifier = {", cm , "};\n",
        "libff::bit_vector secret = {", secret , "};\n"
    );
    console.log("Error value: ", err);
    console.log("Success value: ", success);
});
