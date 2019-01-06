const crypto = require('crypto');
const web3 = require('web3');

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Miximus = artifacts.require("./Miximus.sol");
const Verifier = artifacts.require("./Verifier.sol");
const Pairing = artifacts.require("./Pairing.sol");

function prefixHexadecimalString(hex_str) {
  return "0x" + hex_str;
}

contract('Miximus', (accounts) => {
  it('Test deposit on the mixer', async () => {
    // We have a merkle tree of depth 3 for the tests
    let instance = await Miximus.deployed();

    // --- Leaves layer (layer 3) --- //
    // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
    var testCommitment = crypto.createHash('sha256').update("test-commitment").digest('hex');

    // --- The accounts[0] does the deposit (sender) --- //
    // We have a mixer of std denom of 2 ether --> see migration file
    await instance.deposit("0x" + testCommitment, {from: accounts[0], value: web3.toWei(2, 'ether')});
  });
});
