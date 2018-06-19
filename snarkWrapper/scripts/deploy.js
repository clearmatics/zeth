var Web3 = require('web3');
var Solidity = require('solc')
var fs = require("fs");

// Get verification key
var vk = require('../../zksnark_element/vk.json');

// Hack until solidity allows passing two dimentional arrays
var tmp = []
for (var i = 0; i < vk.IC.length; i++) {
    tmp = [].concat(tmp, vk.IC[i])
}
vk.IC = tmp;

var input = {
    'Miximus.sol': fs.readFileSync("../contracts/Miximus.sol", "utf8"),
    'Verifier.sol': fs.readFileSync("../contracts/Verifier.sol", "utf8"), 
    'MerkleTree.sol': fs.readFileSync("../contracts/MerkleTree.sol", "utf8"),
    'Pairing.sol': fs.readFileSync("../contracts/Pairing.sol", "utf8")
}

// Compilation of the smart contracts
var compiled = Solidity.compile({sources: input}, 1)
console.log(compiled);

var verifier_bytecode = compiled.contracts["Verifier.sol:Verifier"].bytecode;
var verifier_abi = compiled.contracts["Verifier.sol:Verifier"].interface;

var miximus_bytecode = compiled.contracts["Miximus.sol:Miximus"].bytecode;
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
miximus = web3.eth.contract(miximus_abi);
verifier.new(
    vk.a[0], 
    vk.a[1],  
    vk.b, 
    vk.c[0], 
    vk.c[1],
    vk.g[0], 
    vk.g[1], 
    vk.gb1, 
    vk.gb2[0], 
    vk.gb2[1],
    vk.z[0], 
    vk.z[1],
    vk.IC,  
    {
        from: web3.eth.accounts[1], 
        data: verifier_bytecode, 
        gas: '5000000'
    }, function (e, contract){
        console.log("[DEBUG] Deploying verifier", e);
        if (typeof contract.address !== 'undefined') { // If the deployment of the Verifier contract has been successful, then we can deploy
            // the Miximus contract (because the Miximus contract constructor takes the address of the verifier as argument)
            verifier_deployed = verifier.at(contract.address);
            console.log("[DEBUG] Verifier Address: ", verifier_deployed.address);
            console.log("[DEBUG] ICLen:: ", verifier_deployed.getICLen.call());
            miximus.new(verifier_deployed.address, {
                from:web3.eth.accounts[1],
                data: miximus_bytecode,
                gas: '6000000'
            }, function(e, contract) {
                console.log("[DEBUG] Deploy mixer", e);
                if (typeof contract.address !== 'undefined') {
                    console.log("[DEBUG] Deployed err: ", e);
                    miximus_deployed = contract;
                    console.log("[DEBUG] Miximus Address: ", miximus_deployed.address); // Logs the address of the Miximus contract
                }   
            });
        }
    }
)
