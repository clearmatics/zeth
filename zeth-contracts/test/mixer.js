const crypto = require('crypto');
var Web3 = require('web3');

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

contract('Miximus', (accounts) => {
  it('Test deposit on the mixer', async () => {
    // We have a merkle tree of depth 3 for the tests
    let instance = await Miximus.deployed();

    // --- Leaves layer (layer 3) --- //
    // We insert at the first available leaf (leftmost leaf --> index 7 in the tree of depth 3)
    var testCommitment = crypto.createHash('sha256').update("test-commitment").digest('hex');

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
    var txInfo = await instance.deposit("0x" + testCommitment, {from: account0, value: web3.utils.toWei('2', 'ether')});
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

    // --- Generate a proof to initiate the withdrawal --- //
    const { exec } = require('child_process');
    exec('zeth prove', (err, stdout, stderr) => {
      if (err) {
        console.log("Couldn't execute the command");
        return;
      }
      // The *entire* stdout and stderr (buffered)
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    });

    // --- The accounts[1] does the withdrawal (recipient) --- //
    //var account1 = accounts[1];
    //var initialBalanceAccount1 = await web3.eth.getBalance(account1);
    //txInfo = await instance.withdraw("0x" + testCommitment, {from: account1});
    //var balanceAccount1 = await web3.eth.getBalance(account1);
    //// Get the gas cost of the deposit function to do a precise assert
    //tx = await web3.eth.getTransaction(txInfo.tx);
    //gasCost = (tx.gasPrice) * (txInfo.receipt.gasUsed);
    //assert.equal(
    //  balanceAccount1,
    //  initialBalanceAccount1 + Number(web3.utils.toWei('2', 'ether') - gasCost),
    //  "Wrong balance for the account1: Should be increased by 2 from the initial balance"
    //);

    //var balanceMixerAfterWithdrawal = await web3.eth.getBalance(accountMixer);
    //assert.equal(
    //  balanceMixerAfterDeposit,
    //  web3.utils.toWei('0', 'ether'),
    //  "Wrong balance for the accountMixer: Should be 0"
    //);
  });
});
