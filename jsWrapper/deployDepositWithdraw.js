var Web3 = require('web3');
var Solidity = require('solc')
var fs = require("fs");
var BigNumber = require('bignumber.js');

// Get verification key and proving key
var proof = require('../zksnark_element/proof.json');
var vk = require('../zksnark_element/vk.json');

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

var sender_account = web3.eth.accounts[0];
var recipient_account = web3.eth.accounts[1];
var deployer_account = web3.eth.accounts[2];

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
        from: deployer_account,
        data: verifier_bytecode, 
        gas: '5000000'
    }, function (err, contract){
        if (err !== null) {
            console.log("Error while deploying the verifier contract");
            return;
        } else {
            console.log("Verifier contract deployed successfully");
        }
        if (typeof contract.address !== 'undefined') {
            verifier_deployed = verifier.at(contract.address);
            miximus.new(verifier_deployed.address, {
                from: deployer_account,
                data: miximus_bytecode,
                gas: '6000000'
            }, function(err, contract) {
                if (err !== null) {
                    console.log("Error while deploying the Miximus contract");
                    return;
                } else {
                    console.log("Miximus contract deployed successfully");
                }
                if (typeof contract.address !== 'undefined') {
                    miximus_deployed = contract;
                    nullifier = recipient_account + "FFFFFFFFFFFFFFFFFFFFFFFA"; // Hardcoded salt (used for testing purpose)
                    sk = "0xc9b94d9a757f6a57e38809be7dca7599fb0d1bb5ee6b2e7c685092dd8b5e71db"; // Hardcoded secret (testing purpose)
                    miximus_deployed.getSha256(nullifier, sk, function (e, leaf) { 
                        console.log("DEBUG: Balance of sender BEFORE deposit: ", web3.eth.getBalance(sender_account));
                        console.log("DEBUG: Balance of recipient BEFORE deposit: ", web3.eth.getBalance(recipient_account));
                        miximus_deployed.deposit(leaf, {from: sender_account, gas: 6000000, value: web3.toWei(1,"ether")}, function(err, success) {
                            console.log(miximus_deployed.getTree());
                            console.log("DEBUG: Balance of sender AFTER deposit: ", web3.eth.getBalance(sender_account));
                            console.log("DEBUG: Balance of recipient AFTER deposit: ", web3.eth.getBalance(recipient_account));
                            console.log("DEBUG: Balance of contract AFTER deposit: ", web3.eth.getBalance(miximus_deployed.address));
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
                                {from: recipient_account, gas:6000000}, function (err, res) {
                                    if (err !== null) {
                                        console.log("[ERROR] Cannot withdraw from contract: ", err);
                                    } else {
                                        console.log("DEBUG: Balance of sender AFTER withdraw: ", web3.eth.getBalance(sender_account));
                                        console.log("DEBUG: Balance of recipient AFTER withdraw: ", web3.eth.getBalance(recipient_account));
                                        console.log("DEBUG: Balance of contract AFTER withdraw: ", web3.eth.getBalance(miximus_deployed.address));
                                        miximus_deployed.getTree();
                                    }
                                });
                        });
                    });
                }   
            });
        }
    }
)
