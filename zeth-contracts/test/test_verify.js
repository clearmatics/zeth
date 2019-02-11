const crypto = require('crypto');
var Web3 = require('web3');

var abi = require('ethereumjs-abi');

const stripHexPrefix = require('strip-hex-prefix');
const shellescape = require('shell-escape');
const fs = require('fs');

const Verifier = artifacts.require("./Verifier.sol");
const WrapperVerifier = artifacts.require("./WrapperVerifier.sol");
const Pairing = artifacts.require("./Pairing.sol");

const path = require("path");
const debug_path = process.env.ZETH_DEBUG_DIR;
const extended_proof_json = path.join(debug_path, 'invalid_proof_and_input.json');

if (typeof web3 !== 'undefined') {
  web3 = new Web3(web3.currentProvider);
} else {
  // Set the provider you want from Web3.providers
  web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"))
}

contract('WrapperVerifier', (accounts) => {
  it('Verifying proof on-chain', async () => {
    let instance = await WrapperVerifier.deployed();
    var extended_proof_to_verify = JSON.parse(fs.readFileSync(extended_proof_json, 'utf8'));
    var txInfo = await instance.verify(
      extended_proof_to_verify.a,
      extended_proof_to_verify.a_p,
      extended_proof_to_verify.b,
      extended_proof_to_verify.b_p,
      extended_proof_to_verify.c,
      extended_proof_to_verify.c_p,
      extended_proof_to_verify.h,
      extended_proof_to_verify.k,
      extended_proof_to_verify.input,
      {from: accounts[1]}
    );

    assert.equal(
      "LogDebug",
      txInfo.receipt.logs[0].event,
      "The first event emitted should be LogDebug"
    );

    var text_emitted = txInfo.receipt.logs[0].args["text"];
    console.log("Emitted text: ",  text_emitted);
  });
});
