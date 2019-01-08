const crypto = require('crypto');
var Web3 = require('web3');

const stripHexPrefix = require('strip-hex-prefix');
const shellescape = require('shell-escape');
const fs = require('fs');

const { execSync } = require('child_process');

const MerkleTreeSha256 = artifacts.require("./MerkleTreeSha256.sol");
const Miximus = artifacts.require("./Miximus.sol");
const Verifier = artifacts.require("./Verifier.sol");
const Pairing = artifacts.require("./Pairing.sol");

function prefixHexadecimalString(hex_str) {
  return "0x" + hex_str;
}

if (typeof web3 !== 'undefined') {
  web3 = new Web3(web3.currentProvider);
} else {
  // Set the provider you want from Web3.providers
  web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"))
}

function getNullifier(recipientAddr) {
  var hardcoded_salt = "FFFFFFFFFFFFFFFFFFFFFFFA"; // For testing purpose obviously
  var nullifier = stripHexPrefix(recipientAddr + hardcoded_salt);
  console.log("[INFO] Nullifier: " + nullifier);
  return nullifier;
}

// --- Wrapper arounf the zeth CLI --- //
function zethProve(args) {
  var cmd_str = shellescape(["zeth"].concat(args)).toString().trim("\n");
  console.log("[INFO] Running command: " + cmd_str);
  return execSync(shellescape(["zeth"].concat(args))).toString().trim("\n");
}

contract('Miximus', (accounts) => {
  it('Test deposit on the mixer', async () => {
    // We have a merkle tree of depth 3 for the tests
    let instance = await Miximus.deployed();

    // --- Leaves layer (layer 3) --- //
    // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
    var secret = crypto.createHash('sha256').update("test-secret").digest('hex');
    var nullifier = getNullifier(accounts[1]); // accounts[1] is the recipient
    let commitment = crypto.createHash('sha256').
            update(Buffer.from(nullifier + secret, 'hex')).
            digest('hex');

    // --- The accounts[0] does the deposit (sender) --- //
    // We have a mixer of std denom of 2 ether --> see migration file
    var account0 = accounts[0];
    var accountMixer = instance.address;
    var initialBalanceMixer = await web3.eth.getBalance(accountMixer);
    assert.equal(
      initialBalanceMixer,
      web3.utils.toWei('0', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );

    var initialBalanceAccount0 = await web3.eth.getBalance(account0);
    var txInfo = await instance.deposit("0x" + commitment, {from: account0, value: web3.utils.toWei('2', 'ether')});
    var balanceAccount0 = await web3.eth.getBalance(account0);
    // Get the gas cost of the deposit function to do a precise assert
    var tx = await web3.eth.getTransaction(txInfo.tx);
    var gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
    assert.equal(
      balanceAccount0,
      initialBalanceAccount0 - (Number(web3.utils.toWei('2', 'ether')) + gasCost),
      "Wrong balance for the account0: Should be decreased by 2 from the initial balance"
    );

    var balanceMixerAfterDeposit = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balanceMixerAfterDeposit,
      web3.utils.toWei('2', 'ether'),
      "Wrong balance for the accountMixer: Should be 2"
    );

    // Get the merkle tree after insertion to generate the proof
    let tree = await instance.getTree({from: accounts[2]});
    for(var i = 0; i < tree.length; i++) {
      console.log("Node(" + i + ") =>" + tree[i]);
    }
    let root = stripHexPrefix(tree[0]);
    console.log("Root => " + root);
    let commitment_inserted = tree[15];
    console.log("Commitment inserted => " + commitment_inserted);
    assert.equal(
      stripHexPrefix(commitment_inserted),
      commitment,
      "The commitment read from the tree should be equal to the one appended"
    )

    // Get merkle root and merkle path for the commitment at node 15 in the tree
    // (The address of the commitment is 0 since the address is relative to the leaves array)
    let node16 = stripHexPrefix(tree[16]);
    let node8= stripHexPrefix(tree[8]);
    let node4= stripHexPrefix(tree[4]);
    let node2 = stripHexPrefix(tree[2]);
    let tree_depth = 4; // need to match the tree depth that is used to instantiate the cli (tree depth we used for the trsuted setup)
    let address = 0;

    // Invoke the CLI prove command
    zethProve(["prove", tree_depth, address, secret, nullifier, commitment, root, node2, node4, node8, node16]);

    var path = require('path');
    var debug_path = process.env.ZETH_DEBUG_DIR;
    var extended_proof_json = path.join(debug_path, 'proof_and_input.json');
    var extended_proof = require(extended_proof_json);

    // --- The accounts[1] does the withdrawal (recipient) --- //
    var account1 = accounts[1];
    var initialBalanceAccount1 = await web3.eth.getBalance(account1);
    txInfo = await instance.withdraw(
      extended_proof.a,
      extended_proof.a_p,
      extended_proof.b,
      extended_proof.b_p,
      extended_proof.c,
      extended_proof.c_p,
      extended_proof.h,
      extended_proof.k,
      extended_proof.input,
      {from: account1}
    );
    var balanceAccount1 = await web3.eth.getBalance(account1);

    // Get the gas cost of the withdrawal function to do a precise assert
    tx = await web3.eth.getTransaction(txInfo.tx);
    gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
    assert.equal(
      balanceAccount1,
      (initialBalanceAccount1 - gasCost) + Number(web3.utils.toWei('2', 'ether')),
      "Wrong balance for the account1: Should be increased by 2 from the initial balance"
    );

    var balanceMixerAfterWithdrawal = await web3.eth.getBalance(accountMixer);
    assert.equal(
      balanceMixerAfterWithdrawal,
      web3.utils.toWei('0', 'ether'),
      "Wrong balance for the accountMixer: Should be 0"
    );
  });
});
