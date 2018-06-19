var Web3 = require('web3');
var Solidity = require('solc')
var fs = require("fs");

// Get the proof
var proof = require('../../zksnark_element/proof.json');

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

console.log(" --- [DEBUG] Balances BEFORE withdraw --- ");
console.log("Sender: ", web3.eth.getBalance(sender));
console.log("Recipient: ", web3.eth.getBalance(recipient));
console.log("Mixer: ", web3.eth.getBalance(miximus_deployed.address));
miximus_deployed.withdraw(
    proof.a,
    proof.a_p,
    proof.b,
    proof.b_p,
    proof.c,
    proof.c_p,
    proof.h,
    proof.k,
    proof.input,
    {from:recipient, gas:60000000}, function(err, res) {
        console.log("[DEBUG] Verified: ", res, err);
        console.log(" --- [DEBUG] Balances AFTER withdraw --- ");
        console.log("Sender: ", web3.eth.getBalance(sender));
        console.log("Recipient: ", web3.eth.getBalance(recipient));
        console.log("Mixer: ", web3.eth.getBalance(miximus_deployed.address));
        console.log("Error value: ", err);
        console.log("Res value: ", res);
    }
);
